import aiosmtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from jinja2 import Environment, FileSystemLoader, select_autoescape
import os
from app.settings import Settings


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
            template_html = self.jinja_env.get_template("resend-verification_email.html")
            template_text = self.jinja_env.get_template("resend-verification_email.txt")

            # Rendre les templates
            body_html = template_html.render(
                verification_link=verification_link, 
                username=username
            )
            body_text = template_text.render(
                verification_link=verification_link, 
                username=username
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
            print(f"Erreur lors de l'envoi de l'email de renvoi: {e}")
            return False
            """Renvoyer un email de vérification"""
            user = await self.user_repo.get_user_by_email(email)
            
            if not user:
                raise ValueError("Aucun utilisateur trouvé avec cet email")
            
            if user.is_active:
                raise ValueError("Ce compte est déjà activé")
            
            await self.user_repo.delete_user_tokens(user.id)
            raw_token = self._generate_token()
            
            await self.user_repo.create_verification_token(
                user_id=user.id,
                token=raw_token,
                expiry_delay=self.settings.verification.token_expiry_delay
            )
            
            signed_token = self._sign_token(user.id, raw_token)
            verification_url = (
                f"{self.settings.verification.base_url}/users/verify-email/{signed_token}"
            )
            
            # Utiliser la méthode personnalisée pour le renvoi
            email_sent = await self.email_service.send_resend_verification_email(
                to=user.email,
                verification_link=verification_url,
                username=user.username
            )
            
            logger.info(f"Verification email resent to: {email}")
            return email_sent