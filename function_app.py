import azure.functions as func
import logging
from azure.functions.decorators import FunctionApp

app = FunctionApp()

@app.route(route="/")
def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Python HTTP trigger function processed a request.")
    return func.HttpResponse(
        "Hello from The R.oB. Vault Azure Function!",
        status_code=200
    )
