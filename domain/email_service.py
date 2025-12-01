import aiosmtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from jinja2 import Environment, FileSystemLoader, select_autoescape
import os
from app.settings import Settings
import logging

logger = logging.getLogger(__name__)


class EmailService:
    def __init__(self, settings: Settings):
        self.smtp_host = settings.email.smtp_host
        self.smtp_port = settings.email.smtp_port
        self.smtp_user = settings.email.smtp_username
        self.smtp_password = settings.email.smtp_password
        self.from_email = settings.email.from_email
        self.from_name = settings.email.from_name
        self.start_tls = settings.email.use_tls

        # Configuration Jinja2 pour les templates d'emails
        template_dir = os.path.join(
            os.path.dirname(__file__), "..", "app", "views", "emails"
        )
        self.jinja_env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(["html", "xml"]),
        )

    async def send_email(
        self, to: str, subject: str, body_html: str, body_text: str = None
    ) -> None:
        """
        Envoie un email générique
        """
        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = (
            f"{self.from_name} <{self.from_email}>"
            if self.from_name
            else self.from_email
        )
        message["To"] = to

        # Ajouter la version texte brut
        if body_text:
            part_text = MIMEText(body_text, "plain")
            message.attach(part_text)

        # Ajouter la version HTML
        part_html = MIMEText(body_html, "html")
        message.attach(part_html)

        # Envoi asynchrone via SMTP
        try:
            await aiosmtplib.send(
                message,
                hostname=self.smtp_host,
                port=self.smtp_port,
                username=self.smtp_user,
                password=self.smtp_password,
                start_tls=self.start_tls,
            )
        except Exception as e:
            print(f"Erreur lors de l'envoi de l'email: {e}")
            raise

    async def send_verification_email(
        self, to: str, verification_link: str, username: str
    ) -> bool:
        """
        Envoie l'email de vérification avec le lien d'activation
        """
        # Charger les templates
        template_html = self.jinja_env.get_template("register-verification_email.html")
        template_text = self.jinja_env.get_template("register-verification_email.txt")

        # Rendre les templates
        body_html = template_html.render(
            verification_link=verification_link, username=username
        )
        body_text = template_text.render(
            verification_link=verification_link, username=username
        )

        # Envoyer l'email
        await self.send_email(
            to=to,
            subject="Activez votre compte",
            body_html=body_html,
            body_text=body_text,
        )

        return True

    async def send_resend_verification_email(
        self, to: str, verification_link: str, username: str
    ) -> bool:
        """
        Envoie l'email de renvoi de vérification (personnalisé)
        """
        try:
            # Charger les templates
            template_html = self.jinja_env.get_template(
                "resend-verification_email.html"
            )
            template_text = self.jinja_env.get_template("resend-verification_email.txt")

            # Rendre les templates
            body_html = template_html.render(
                verification_link=verification_link, username=username
            )
            body_text = template_text.render(
                verification_link=verification_link, username=username
            )

            # Envoyer l'email
            await self.send_email(
                to=to,
                subject="🔄 Nouveau lien de vérification",
                body_html=body_html,
                body_text=body_text,
            )
            return True
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi de l'email de renvoi: {e}")
            return False

    async def send_password_reset_email(
        self, to: str, reset_link: str, username: str
    ) -> bool:
        """
        Envoie l'email de réinitialisation de mot de passe
        """
        try:
            # Charger les templates
            template_html = self.jinja_env.get_template("password_reset_email.html")
            template_text = self.jinja_env.get_template("password_reset_email.txt")

            # Rendre les templates
            body_html = template_html.render(reset_link=reset_link, username=username)
            body_text = template_text.render(reset_link=reset_link, username=username)

            # Envoyer l'email
            await self.send_email(
                to=to,
                subject="🔒 Réinitialisation de votre mot de passe",
                body_html=body_html,
                body_text=body_text,
            )
            return True
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi de l'email de reset: {e}")
            return False

    # ==========================================
    # ⭐ NOUVEAUX EMAILS - Architecture modulaire
    # ==========================================

    async def send_account_creation_confirmation(
        self, to: str, username: str
    ) -> bool:
        """
        Envoie un email de confirmation de création de compte
        (envoyé immédiatement après la création du compte)
        """
        try:
            subject = "✅ Votre compte a été créé avec succès"
            body_html = f"""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #4CAF50;">Compte créé avec succès !</h2>
                    <p>Bonjour <strong>{username}</strong>,</p>
                    <p>Votre compte a été créé avec succès. Vous allez recevoir un email de vérification dans quelques instants.</p>
                    <p>Veuillez cliquer sur le lien dans cet email pour activer votre compte.</p>
                    <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
                    <p style="color: #666; font-size: 12px;">
                        Cet email a été envoyé automatiquement. Merci de ne pas y répondre.
                    </p>
                </div>
            </body>
            </html>
            """
            body_text = f"""
Compte créé avec succès !

Bonjour {username},

Votre compte a été créé avec succès. Vous allez recevoir un email de vérification dans quelques instants.

Veuillez cliquer sur le lien dans cet email pour activer votre compte.

---
Cet email a été envoyé automatiquement. Merci de ne pas y répondre.
            """

            await self.send_email(
                to=to,
                subject=subject,
                body_html=body_html,
                body_text=body_text,
            )
            logger.info(f"Account creation confirmation sent to: {to}")
            return True
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi de l'email de confirmation: {e}")
            return False

    async def send_thank_you_email(self, to: str, username: str) -> bool:
        """
        Envoie un email de remerciement après activation du compte
        """
        try:
            subject = "🙏 Merci d'avoir activé votre compte"
            body_html = f"""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #2196F3;">Merci {username} !</h2>
                    <p>Votre compte a été activé avec succès.</p>
                    <p>Nous vous remercions d'avoir pris le temps de vérifier votre email.</p>
                    <p>Vous pouvez maintenant vous connecter et profiter de toutes les fonctionnalités de notre plateforme.</p>
                    <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
                    <p style="color: #666; font-size: 12px;">
                        Cet email a été envoyé automatiquement. Merci de ne pas y répondre.
                    </p>
                </div>
            </body>
            </html>
            """
            body_text = f"""
Merci {username} !

Votre compte a été activé avec succès.

Nous vous remercions d'avoir pris le temps de vérifier votre email.

Vous pouvez maintenant vous connecter et profiter de toutes les fonctionnalités de notre plateforme.

---
Cet email a été envoyé automatiquement. Merci de ne pas y répondre.
            """

            await self.send_email(
                to=to,
                subject=subject,
                body_html=body_html,
                body_text=body_text,
            )
            logger.info(f"Thank you email sent to: {to}")
            return True
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi de l'email de remerciement: {e}")
            return False

    async def send_welcome_email(self, to: str, username: str) -> bool:
        """
        Envoie un email de bienvenue après activation du compte
        """
        try:
            subject = "🎉 Bienvenue sur notre plateforme !"
            body_html = f"""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #FF9800;">🎉 Bienvenue {username} !</h2>
                    <p>Nous sommes ravis de vous accueillir sur notre plateforme.</p>
                    <p>Voici quelques conseils pour bien démarrer :</p>
                    <ul>
                        <li>Complétez votre profil</li>
                        <li>Explorez les fonctionnalités</li>
                        <li>Rejoignez notre communauté</li>
                    </ul>
                    <p>Si vous avez des questions, n'hésitez pas à nous contacter.</p>
                    <p style="margin-top: 30px;">
                        <strong>L'équipe</strong>
                    </p>
                    <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
                    <p style="color: #666; font-size: 12px;">
                        Cet email a été envoyé automatiquement. Merci de ne pas y répondre.
                    </p>
                </div>
            </body>
            </html>
            """
            body_text = f"""
🎉 Bienvenue {username} !

Nous sommes ravis de vous accueillir sur notre plateforme.

Voici quelques conseils pour bien démarrer :
- Complétez votre profil
- Explorez les fonctionnalités
- Rejoignez notre communauté

Si vous avez des questions, n'hésitez pas à nous contacter.

L'équipe

---
Cet email a été envoyé automatiquement. Merci de ne pas y répondre.
            """

            await self.send_email(
                to=to,
                subject=subject,
                body_html=body_html,
                body_text=body_text,
            )
            logger.info(f"Welcome email sent to: {to}")
            return True
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi de l'email de bienvenue: {e}")
            return False
