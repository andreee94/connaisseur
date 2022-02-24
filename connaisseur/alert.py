import json
import logging
import os
from datetime import datetime
from typing import Optional

import requests
from jinja2 import StrictUndefined, Template

from connaisseur.util import safe_json_open, validate_schema
from connaisseur.exceptions import (
    AlertSendingError,
    ConfigurationError,
    InvalidConfigurationFormatError,
    InvalidImageFormatError,
)
from connaisseur.admission_request import AdmissionRequest


class AlertingConfiguration:

    __PATH = "/app/config/alertconfig.json"
    __SCHEMA_PATH = "/app/connaisseur/res/alertconfig_schema.json"

    config: dict

    def __init__(self):
        try:
            self.config = safe_json_open("/app/config", self.__PATH)
            validate_schema(
                self.config,
                self.__SCHEMA_PATH,
                "AlertingConfiguration",
                InvalidConfigurationFormatError,
            )
        except FileNotFoundError:
            logging.debug("No alerting configuration file found.")
            self.config = {}
        except InvalidConfigurationFormatError as err:
            raise ConfigurationError(err.message) from err
        except Exception as err:
            raise ConfigurationError(
                "An error occurred while loading the AlertingConfiguration file:"
                f"{str(err)}"
            ) from err

    def alerting_required(self, event_category: str) -> bool:
        return bool(self.config.get(event_category))


class AlertReceiverAuthentication:
    """
    Class to store authentication information for securely sending events to the alert receiver.
    """

    class AlertReceiverBasicAuthentication:
        """
        Class to store authentication information for basic authentication type with username and password.
        """
        username: str
        password: str
        authentication_type: str
        authorization_prefix: str = "Basic"

        def __init__(self, alert_receiver_config: dict):
            basic_authentication_config = alert_receiver_config.get(
                "receiver_authentication_basic", None
            )

            if (
                basic_authentication_config is None
            ):  # TODO maybe remove this check since it is included in the json validation?
                raise ConfigurationError("No basic authentication configuration found.")

            username_env = basic_authentication_config.get("username_env", None)
            password_env = basic_authentication_config.get("password_env", None)

            if (
                username_env is None or password_env is None
            ):  # TODO maybe remove this check since it is included in the json validation?
                raise ConfigurationError(
                    "No username_env or password_env configuration found."
                )

            self.username = os.environ.get(username_env, None)
            self.password = os.environ.get(password_env, None)

            if self.username is None or self.password is None:
                raise ConfigurationError(
                    f"No username or password found from environmental variables {username_env} and {password_env}."
                )

            self.authorization_prefix = basic_authentication_config.get(
                "authorization_prefix", "Basic"
            )
            # TODO maybe validate authorization prefix

        def get_header(self) -> dict:
            return {
                "Authorization": f"{self.authorization_prefix} {self.username}:{self.password}"
            }

    class AlertReceiverBearerAuthentication:
        """
        Class to store authentication information for bearer authentication type which uses a token.
        """
        token: str
        authorization_prefix: str = "Bearer"  # default is bearer

        def __init__(self, alert_receiver_config: dict):
            bearer_authentication_config = alert_receiver_config.get(
                "receiver_authentication_bearer", None
            )

            if (
                bearer_authentication_config is None
            ):  # TODO maybe remove this check since it is included in the json validation?
                raise ConfigurationError(
                    "No bearer authentication configuration found."
                )

            token_env = bearer_authentication_config.get("token_env", None)
            token_file = bearer_authentication_config.get("token_file", None)

            if (
                token_env is None and token_file is None
            ):  # TODO maybe remove this check since it is included in the json validation?
                raise ConfigurationError(
                    "No token_env and token_file configuration found."
                )

            if (
                token_env is not None and token_file is not None
            ):  # TODO maybe remove this check since it is included in the json validation?
                raise ConfigurationError(
                    "Both token_env and token_file configuration found. Only one is required."
                )

            if token_env is not None:
                self.token = os.environ.get(token_env, None)

                if self.token is None:
                    raise ConfigurationError(
                        f"No token found from environmental variable {token_env}."
                    )
            else:
                try:
                    with open(token_file, "r") as token_file:
                        self.token = token_file.read()
                except FileNotFoundError:
                    raise ConfigurationError(f"No token file found at {token_file}.")
                except Exception as err:
                    raise ConfigurationError(
                        f"An error occurred while loading the token file {token_file}: {str(err)}"
                    )

            self.authorization_prefix = bearer_authentication_config.get(
                "authorization_prefix", "Bearer"
            )
            # TODO maybe validate authorization prefix

        def get_header(self) -> dict:
            return {"Authorization": f"{self.authorization_prefix} {self.token}"}

    def __init__(self, alert_receiver_config: dict):
        self.authentication_type = alert_receiver_config.get(
            "receiver_authentication_type", "none"
        )

        if self.is_basic():
            self.__init_basic_authentication(alert_receiver_config)
        elif self.is_bearer():
            self.__init_bearer_authentication(alert_receiver_config)

    def is_basic(self):
        return self.authentication_type == "basic"

    def is_bearer(self):
        return self.authentication_type == "bearer"

    def is_none(self):
        return self.authentication_type == "none"

    def __init_bearer_authentication(self, alert_receiver_config: dict):
        self.bearer_authentication = (
            AlertReceiverAuthentication.AlertReceiverBearerAuthentication(
                alert_receiver_config
            )
        )

    def __init_basic_authentication(self, alert_receiver_config: dict):
        self.basic_authentication = (
            AlertReceiverAuthentication.AlertReceiverBasicAuthentication(
                alert_receiver_config
            )
        )

    def get_auth_header(self) -> dict:
        if self.is_basic():
            return self.basic_authentication.get_header()
        elif self.is_bearer():
            return self.bearer_authentication.get_header()
        elif self.is_none():
            return {}
        else:
            raise ConfigurationError(
                "No authentication type found."
            )  # hopefully this never happens


class Alert:
    """
    Class to store image information about an alert as attributes and a sending
    functionality as method.
    Alert sending can, depending on the configuration, throw an AlertSendingError
    causing Connaisseur to respond with status code 500 to the request that was sent
    for admission control, causing a Kubernetes Error event.
    """

    template: str
    receiver_url: str
    receiver_authentication: AlertReceiverAuthentication
    payload: str
    headers: dict

    context: dict
    throw_if_alert_sending_fails: bool

    __TEMPLATE_PATH = "/app/config/templates"

    def __init__(
        self,
        alert_message: str,
        receiver_config: dict,
        admission_request: AdmissionRequest,
    ):
        if admission_request is None:
            images = "Invalid admission request."
            namespace = "Invalid admission request."
            request_id = "Invalid admission request."
        else:
            namespace = admission_request.namespace
            request_id = admission_request.uid
            try:
                images = str(
                    [
                        str(image)
                        for image in admission_request.wl_object.containers.values()
                    ]
                )
            except InvalidImageFormatError:
                images = "Error retrieving images."

        self.context = {
            "alert_message": alert_message,
            "priority": str(receiver_config.get("priority", 3)),
            "connaisseur_pod_id": os.getenv("POD_NAME"),
            "cluster": os.getenv("CLUSTER_NAME"),
            "namespace": namespace,
            "timestamp": datetime.now(),
            "request_id": request_id or "No given UID",
            "images": images,
        }
        self.receiver_url = receiver_config["receiver_url"]
        self.receiver_authentication = AlertReceiverAuthentication(receiver_config)
        self.template = receiver_config["template"]
        self.throw_if_alert_sending_fails = receiver_config.get(
            "fail_if_alert_sending_fails", False
        )
        self.payload = self.__construct_payload(receiver_config)
        self.headers = self.__get_headers(receiver_config, self.receiver_authentication)

    def __construct_payload(self, receiver_config: dict) -> str:
        try:
            template = safe_json_open(
                self.__TEMPLATE_PATH, f"{self.__TEMPLATE_PATH}/{self.template}.json"
            )
        except FileNotFoundError as err:
            raise ConfigurationError(
                f"Unable to find template file {self.template}."
            ) from err
        except Exception as err:
            raise ConfigurationError(
                f"Error loading template file {self.template}: {str(err)}"
            ) from err
        payload = self.__render_template(template)
        if receiver_config.get("payload_fields") is not None:
            payload.update(receiver_config.get("payload_fields"))
        return json.dumps(payload)

    def __render_template(self, template):
        if isinstance(template, dict):
            for key in template.keys():
                template[key] = self.__render_template(template[key])
        elif isinstance(template, list):
            template[:] = [self.__render_template(entry) for entry in template]
        elif isinstance(template, str):
            template = Template(template).render(
                self.context, undefined=StrictUndefined
            )
        return template

    def send_alert(self) -> Optional[requests.Response]:
        response = None
        try:
            response = requests.post(
                self.receiver_url, data=self.payload, headers=self.headers
            )
            response.raise_for_status()
            logging.info("sent alert to %s", self.template)
        except Exception as err:
            logging.error(err)
            if self.throw_if_alert_sending_fails:
                raise AlertSendingError(str(err)) from err
        return response

    @staticmethod
    def __get_headers(
        receiver_config: dict, receiver_authentication: AlertReceiverAuthentication
    ) -> dict:
        headers = {"Content-Type": "application/json"}
        additional_headers = receiver_config.get("custom_headers")
        if additional_headers is not None:
            for header in additional_headers:
                key, value = header.split(":", 1)
                headers.update({key.strip(): value.strip()})
        auth_header = receiver_authentication.get_auth_header()
        if auth_header:  # not None and not empty
            headers.update(auth_header)
        return headers


def send_alerts(
    admission_request: AdmissionRequest, admit_event: bool, reason: str = None
) -> None:
    al_config = AlertingConfiguration()
    event_category = "admit_request" if admit_event else "reject_request"
    if al_config.alerting_required(event_category):
        for receiver in al_config.config[event_category]["templates"]:
            message = (
                "CONNAISSEUR admitted a request."
                if admit_event
                else f"CONNAISSEUR rejected a request: {reason}"
            )
            Alert(message, receiver, admission_request).send_alert()
