from django.conf import settings
import os
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from PyPDF2 import PdfReader
from simple_salesforce import Salesforce
import requests
from rest_framework.permissions import IsAuthenticated
from sentry_sdk import capture_exception
from .authentication import CustomTokenAuthentication
from users.models import SalesforceConnection, APIUsage, APIKey
from datetime import datetime

class DocumentProcessingView(APIView):
    authentication_classes = [CustomTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        document_id = request.data.get("documentId")
        organisation_id = request.data.get("organisationId")

        if not document_id or not organisation_id:
            self.log_api_usage(request.user, None, document_id, "FAILURE", request)
            return Response(
                {"error": "Missing documentId or organisationId"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Create the APIUsage entry
        api_usage = self.log_api_usage(request.user, None, document_id, "PROCESSING", request)
        api_usage.process_start_time = datetime.now()
        api_usage.process_status = "PROCESSING"
        api_usage.save()

        try:
            # Fetch Salesforce connection
            connection = SalesforceConnection.objects.get(
                user=request.user,
                organization_id=organisation_id
            )

            # Fetch file from Salesforce
            file_path = self.fetch_file_from_salesforce(connection.access_token, document_id, connection.instance_url)

            # Process the file
            parsed_text, num_pages, num_characters = self.process_file(file_path)

            # Prepare response data
            response_data = {
                "fileName": os.path.basename(file_path),
                "numPages": num_pages,
                "numCharacters": num_characters,
                "parsedText": parsed_text,
            }

            # Update APIUsage entry on success
            api_usage.process_end_time = datetime.now()
            api_usage.process_status = "SUCCESS"
            api_usage.calculate_process_duration()
            api_usage.save()

            return Response(response_data, status=status.HTTP_200_OK)

        except Exception as e:
            # Handle exception, update status and capture error
            capture_exception(e)

            api_usage.process_end_time = datetime.now()
            api_usage.process_status = "FAILURE"
            api_usage.calculate_process_duration()
            api_usage.save()

            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def fetch_file_from_salesforce(self, access_token, document_id, instance_url):
        """
        Fetch the file's content from Salesforce using access_token and documentId.
        """
        sf = Salesforce(instance_url=instance_url, session_id=access_token)
        query = f"SELECT VersionData, Title, FileExtension FROM ContentVersion WHERE Id = '{document_id}'"
        content_version = sf.query(query)

        if not content_version["records"]:
            raise ValueError(f"No file found for DocumentId {document_id}")

        version_data_relative_url = content_version["records"][0]["VersionData"]
        file_name = content_version["records"][0]["Title"]
        file_extension = content_version["records"][0]["FileExtension"]

        version_data_url = f"{instance_url}{version_data_relative_url}"

        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(version_data_url, headers=headers, stream=True)

        if response.status_code != 200:
            raise ValueError(f"Failed to fetch file content. HTTP Status {response.status_code}")

        file_path = os.path.join(settings.MEDIA_ROOT, f"{file_name}.{file_extension}")
        with open(file_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=1024):
                f.write(chunk)

        return file_path

    def process_file(self, file_path):
        """
        Extract text and metadata from the file.
        """
        file_extension = os.path.splitext(file_path)[1].lower()
        parsed_text = None
        num_pages = 0
        num_characters = 0

        if file_extension == ".pdf":
            parsed_text, num_pages, num_characters = self.extract_text_with_ocr(file_path)

        return parsed_text, num_pages, num_characters

    def extract_text_with_ocr(self, pdf_path):
        """
        Extract text from PDF.
        """
        reader = PdfReader(pdf_path)
        text = ""
        num_pages = len(reader.pages)

        for page in reader.pages:
            extracted_text = page.extract_text()
            text += extracted_text if extracted_text else ""

        num_characters = len(text)
        return text, num_pages, num_characters

    def log_api_usage(self, user, connection, document_id, status, request):
        """
        Logs the overall API usage details to the APIUsage model.
        """
        try:
            token = self.get_token_from_request(request)
            api_key = APIKey.objects.filter(key=token).first()

            # Create APIUsage log
            api_usage = APIUsage.objects.create(
                user=user,
                api_key=api_key,
                salesforce_connection=connection,
                sf_document_id=document_id,
                status=status,
            )
            return api_usage
        except Exception as e:
            capture_exception(e)

    def get_token_from_request(self, request):
        """
        Extracts the token from the Authorization header.
        """
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Token "):
            return auth_header.split()[1]
        return None
