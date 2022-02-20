import asyncio
import json
import logging
import os
import re
import subprocess  # nosec

from connaisseur.exceptions import (
    CosignError,
    CosignTimeout,
    NotFoundException,
    InvalidFormatException,
    UnexpectedCosignData,
    ValidationError,
)
from connaisseur.image import Image
from connaisseur.keys import Key
from connaisseur.util import safe_path_func  # nosec
from connaisseur.validators.interface import ValidatorInterface


class CosignValidator(ValidatorInterface):
    name: str
    trust_roots: list
    vals: dict

    def __init__(self, name: str, trust_roots: list, **kwargs):
        super().__init__(name, **kwargs)
        self.trust_roots = trust_roots
        self.vals = {}

    def __get_key(self, key_name: str = None):
        key_name = key_name or "default"

        if key_name == "*":
            keys = {
                k["name"]: {
                    "name": k["name"],
                    "key": Key("".join(k["key"])),
                    "digest": None,
                    "error": None,
                }
                for k in self.trust_roots
            }
        else:
            try:
                key = next(k["key"] for k in self.trust_roots if k["name"] == key_name)
            except StopIteration as err:
                msg = 'Trust root "{key_name}" not configured for validator "{validator_name}".'
                raise NotFoundException(
                    message=msg, key_name=key_name, validator_name=self.name
                ) from err
            keys = {
                key_name: {
                    "name": key_name,
                    "key": Key("".join(key)),
                    "digest": None,
                    "error": None,
                }
            }
        return keys

    async def validate(
        self, image: Image, trust_root: str = None, **kwargs
    ):  # pylint: disable=arguments-differ
        self.vals = self.__get_key(trust_root)

        threshold = kwargs.get(
            "threshold", len(self.trust_roots) if trust_root == "*" else 1
        )
        required = kwargs.get("required", [])

        tasks = [self.__execute_validations(k, image) for k in self.vals.keys()]
        await asyncio.gather(*tasks)

        return CosignValidator.__apply_policy(
            vals=self.vals, threshold=threshold, required=required
        )

    async def __execute_validations(self, trust_root: str, image: str):
        try:
            self.vals[trust_root]["digest"] = await self.__get_cosign_validated_digests(
                image, self.vals[trust_root]
            )
        except Exception as err:
            self.vals[trust_root]["error"] = err
            logging.info(err)

    async def __get_cosign_validated_digests(self, image: Image, trust_root: dict):
        """
        Get and process Cosign validation output for a given `image` and `key`
        and either return a list of valid digests or raise a suitable exception
        in case no valid signature is found or Cosign fails.
        """
        key = trust_root["key"]

        returncode, stdout, stderr = await key.verify(
            validator_type="cosign", cosign_callback=self.__cosign_callback, image=image
        )
        logging.info(
            "COSIGN output of trust root '%s' for image'%s': RETURNCODE: %s; STDOUT: %s; STDERR: %s",
            trust_root["name"],
            str(image),
            returncode,
            stdout,
            stderr,
        )
        digests = []
        if returncode == 0:
            for sig in stdout.splitlines():
                try:
                    sig_data = json.loads(sig)
                    try:
                        digest = sig_data["critical"]["image"].get(
                            "docker-manifest-digest", ""
                        )
                        if re.match(r"sha256:[0-9A-Fa-f]{64}", digest) is None:
                            msg = "Digest '{digest}' does not match expected digest pattern."
                            raise InvalidFormatException(message=msg, digest=digest)
                    except Exception as err:
                        msg = (
                            "Could not retrieve valid and unambiguous digest from data "
                            "received by Cosign: {err_type}: {err}"
                        )
                        raise UnexpectedCosignData(
                            message=msg,
                            err_type=type(err).__name__,
                            err=str(err),
                            trust_data_type="dev.cosignproject.cosign/signature",
                            stderr=stderr,
                            image=str(image),
                            trust_root=trust_root["name"],
                        ) from err
                    # remove prefix 'sha256'
                    digests.append(digest.removeprefix("sha256:"))
                except json.JSONDecodeError:
                    logging.info("non-json signature data from Cosign: %s", sig)
                    pass
        elif "Error: no matching signatures:\nfailed to verify signature\n" in stderr:
            msg = "Failed to verify signature of trust data."
            raise ValidationError(
                message=msg,
                trust_data_type="dev.cosignproject.cosign/signature",
                stderr=stderr,
                image=str(image),
                trust_root=trust_root["name"],
            )
        elif "Error: no matching signatures:\n\nmain.go:" in stderr:
            msg = 'No trust data for image "{image}".'
            raise NotFoundException(
                message=msg,
                trust_data_type="dev.cosignproject.cosign/signature",
                stderr=stderr,
                image=str(image),
                trust_root=trust_root["name"],
            )
        else:
            msg = 'Unexpected Cosign exception for image "{image}": {stderr}.'
            raise CosignError(
                message=msg,
                trust_data_type="dev.cosignproject.cosign/signature",
                stderr=stderr,
                image=str(image),
                trust_root=trust_root["name"],
            )
        if not digests:
            msg = (
                "Could not extract any digest from data received by Cosign "
                "despite successful image verification."
            )
            raise UnexpectedCosignData(
                message=msg,
                trust_data_type="dev.cosignproject.cosign/signature",
                stderr=stderr,
                image=str(image),
                trust_root=trust_root["name"],
            )
        return digests.pop()

    async def __cosign_callback(self, image: Image, key_args: list):
        option_kword, inline_key, key = key_args
        cmd = [
            "/app/cosign/cosign",
            "verify",
            "--output",
            "text",
            option_kword,
            inline_key,
            str(image),
        ]

        with subprocess.Popen(  # nosec
            cmd,
            env=self.__get_envs(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as process:
            try:
                stdout, stderr = process.communicate(key, timeout=60)
            except subprocess.TimeoutExpired as err:
                process.kill()
                msg = "Cosign timed out."
                raise CosignTimeout(
                    message=msg, trust_data_type="dev.cosignproject.cosign/signature"
                ) from err

        return process.returncode, stdout.decode("utf-8"), stderr.decode("utf-8")

    def __get_envs(self):
        env = os.environ.copy()
        # Extend the OS env vars only for passing to the subprocess below
        env["DOCKER_CONFIG"] = f"/app/connaisseur-config/{self.name}/.docker/"
        if safe_path_func(
            os.path.exists, "/app/certs/cosign", f"/app/certs/cosign/{self.name}.crt"
        ):
            env["SSL_CERT_FILE"] = f"/app/certs/cosign/{self.name}.crt"
        return env

    @staticmethod
    def __apply_policy(vals: dict, threshold: int, required: list):
        """
        TODO: applies the validation policy

        TODO: Raises Exception if not compliant
        """

        # verify threshold
        signed_digests = [k["digest"] for k in vals.values() if k["digest"] is not None]
        # check that same digest present 'threshold' times
        if not len(set(signed_digests)) == 1 or not len(signed_digests) >= threshold:
            if len(vals) == 1:
                raise list(vals.values()).pop()["error"]
            else:
                errs = "\n".join(
                    [
                        f"* trust root '{e['name']}': {e['error'].message}"
                        for e in vals.values()
                        if e["error"] is not None
                    ]
                )
                msg = "Image not compliant with validation policy (threshold of '{threshold}' not reached). The following errors occurred (please check the logs for more information):\n{errors}"
                raise ValidationError(
                    message=msg,
                    trust_data_type="dev.cosignproject.cosign/signature",
                    threshold=str(threshold),
                    required=required,
                    errors=errs,
                )
        else:
            digest = set(signed_digests).pop()

        # verify required trust roots
        missing_trust_roots = []
        for trust_root in required:
            if not vals[trust_root]["digest"] == digest:
                missing_trust_roots.append(trust_root)

        if missing_trust_roots:
            errs = "\n".join(
                [
                    f"* trust root '{e['name']}': {e['error'].message}"
                    for e in vals.values()
                    if e["name"] in missing_trust_roots
                ]
            )
            msg = "Image not compliant with validation policy (missing signatures for required trust roots: {missing}). The following errors occurred (please check the logs for more information):\n{errors}"

            raise ValidationError(
                message=msg,
                trust_data_type="dev.cosignproject.cosign/signature",
                threshold=str(threshold),
                required=required,
                missing=", ".join(missing_trust_roots),
                errors=errs,
            )

        return digest

    @property
    def healthy(self):
        return True
