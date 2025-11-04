"""
Application settings handled using essentials-configuration and Pydantic.

- essentials-configuration is used to read settings from various sources and build the
  configuration root
- Pydantic is used to validate application settings

https://github.com/Neoteroi/essentials-configuration

https://docs.pydantic.dev/latest/usage/settings/
"""

from blacksheep.server.env import get_env, is_development
from config.common import Configuration, ConfigurationBuilder
from config.env import EnvVars
from config.user import UserSettings
from config.yaml import YAMLFile
from pydantic import BaseModel
from typing import Optional


class APIInfo(BaseModel):
    title: str
    version: str


class App(BaseModel):
    show_error_details: bool


class Site(BaseModel):
    copyright: str


# Database Configuration
class Database(BaseModel):
    url: str
    echo: bool = False


# Configuration pour la vérification des tokens
class Verification(BaseModel):
    token_expiry_delay: int
    secret: str
    base_url: str


# SMTP Configuration
class Email(BaseModel):
    smtp_host: str
    smtp_port: int
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    from_email: str
    from_name: str
    use_tls: bool


class Settings(BaseModel):
    app: App
    info: APIInfo
    site: Site
    database: Database
    email: Email
    verification: Verification


def default_configuration_builder() -> ConfigurationBuilder:
    app_env = get_env()
    builder = ConfigurationBuilder(
        YAMLFile(f"settings.yaml"),
        YAMLFile(f"settings.{app_env.lower()}.yaml", optional=True),
        EnvVars("APP_"),
    )

    if is_development():
        # for development environment, settings stored in the user folder
        builder.add_source(UserSettings())

    return builder


def default_configuration() -> Configuration:
    builder = default_configuration_builder()

    return builder.build()


def load_settings() -> Settings:
    config_root = default_configuration()
    return config_root.bind(Settings)
