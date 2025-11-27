from typing import Optional

from blacksheep import Request
from blacksheep.server.controllers import Controller, get


class Home(Controller):
    @get()
    def index(self, request: Request):
        # Since the @get() decorator is used without arguments, the URL path
        # is by default "/"

        # Since the view function is called without parameters, the name is
        # obtained from the calling request handler: 'index',
        # -> /views/home/index.jinja
        return self.view(request=request)

    @get(None)
    def example(self, request: Request):
        # Since the @get() decorator is used explicitly with None, the URL path
        # is obtained from the method name: "/example"

        # Since the view function is called without parameters, the name is
        # obtained from the calling request handler: 'example',
        # -> /views/home/example.jinja
        return self.view(request=request)

    @get("/error/rate-limit")
    def rate_limit_error(self, request: Request):
        """
        Page affichée lorsqu'un rate limit est déclenché côté HTML.
        """
        message_param = request.query.get("message")
        retry_param = request.query.get("retry_after")

        message: Optional[str] = (
            message_param[0] if isinstance(message_param, list) and message_param else None
        )
        retry_after: Optional[str] = (
            retry_param[0] if isinstance(retry_param, list) and retry_param else None
        )

        return self.view(
            "rate_limit",
            model={
                "title": "Trop de tentatives",
                "message": message
                or "Vous avez effectué trop d'actions en peu de temps.",
                "retry_after": retry_after,
            },
            request=request,
        )
