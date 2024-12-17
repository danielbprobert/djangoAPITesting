from django.conf import settings
import os
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from PyPDF2 import PdfReader
from pdf2image import convert_from_path
from docx import Document
from openpyxl import load_workbook
from pptx import Presentation
from reportlab.pdfgen import canvas
from simple_salesforce import Salesforce
import requests
from rest_framework.permissions import IsAuthenticated
from django.http import StreamingHttpResponse
from sentry_sdk import capture_exception, capture_message
from .authentication import CustomTokenAuthentication
from users.models import SalesforceConnection


class DocumentProcessingView(APIView):
    authentication_classes = [CustomTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        capture_message("DocumentProcessingView: API POST request received", level="info")
        
        document_id = request.data.get("documentId")
        organisation_id = request.data.get("organisationId")

        capture_message(f"Processing documentId: {document_id}, organisationId: {organisation_id}", level="info")

        if not document_id or not organisation_id:
            return Response(
                {"error": "Missing documentId or organisationId"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Fetch SalesforceConnection for the user using organisation_id
        try:
            connection = SalesforceConnection.objects.get(
                user=request.user,
                organization_id=organisation_id
            )
        except SalesforceConnection.DoesNotExist:
            return Response(
                {"error": "No Salesforce connection found for this organisation"},
                status=status.HTTP_404_NOT_FOUND,
            )

        try:
            # Fetch the file
            file_path = self.fetch_file_from_salesforce(
                connection.access_token, document_id, connection.instance_url
            )

            # Process file to extract text (if it's a PDF)
            file_extension = os.path.splitext(file_path)[1].lower()
            parsed_text = None
            num_pages = 0
            num_characters = 0

            if file_extension == ".pdf":
                parsed_text, num_pages, num_characters = self.extract_text_with_ocr(file_path)

            safe_headers = {
                "Content-Disposition": f"inline; filename=\"{os.path.basename(file_path)}\"",
                "Content-Type": "application/json"
            }

            # Response Data
            response_data = {
                "fileName": os.path.basename(file_path),
                "numPages": num_pages,
                "numCharacters": num_characters,
                "parsedText": parsed_text,
            }
            
            capture_message(f"Response Date: {response_data}", level="info")

            return Response(response_data, headers=safe_headers, status=status.HTTP_200_OK)

        except Exception as e:
            capture_exception(e)
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def fetch_file_from_salesforce(self, access_token, document_id, instance_url):
        """
        Fetch the file's content from Salesforce using access_token and documentId.
        """
        sf = Salesforce(instance_url=instance_url, session_id=access_token)

        # Query for file details
        query = f"SELECT VersionData, Title, FileExtension FROM ContentVersion WHERE Id = '{document_id}'"
        capture_message(f"Executing Salesforce Query: {query}", level="info")
        content_version = sf.query(query)

        if not content_version["records"]:
            raise ValueError(f"No file found for DocumentId {document_id}")

        # Get file metadata
        version_data_relative_url = content_version["records"][0]["VersionData"]
        file_name = content_version["records"][0]["Title"]
        file_extension = content_version["records"][0]["FileExtension"]

        # Construct the full file download URL
        version_data_url = f"{instance_url}{version_data_relative_url}"
        capture_message(f"Fetching file content from URL: {version_data_url}", level="info")

        # Fetch the file content using the access token
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(version_data_url, headers=headers, stream=True)

        if response.status_code != 200:
            raise ValueError(f"Failed to fetch file content. HTTP Status {response.status_code}")

        # Save the file temporarily
        file_path = os.path.join(settings.MEDIA_ROOT, f"{file_name}.{file_extension}")
        with open(file_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=1024):
                f.write(chunk)

        return file_path

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
