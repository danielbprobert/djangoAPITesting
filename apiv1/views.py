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
from .authentication import CustomTokenAuthentication
from sentry_sdk import capture_exception, capture_message
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
            capture_message("Missing required parameters in request", level="warning")
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
            # Fetch file using Salesforce details
            file_path = self.fetch_file_from_salesforce(
                connection.access_token, document_id, connection.instance_url
            )

            # Process the file
            file_extension = os.path.splitext(file_path)[1].lower()
            pdf_path = None

            if file_extension == ".pdf":
                pdf_path = file_path
            elif file_extension in [".jpg", ".jpeg", ".png"]:
                pdf_path = self.convert_image_to_pdf(file_path)
            elif file_extension == ".docx":
                pdf_path = self.convert_docx_to_pdf(file_path)
            elif file_extension in [".xls", ".xlsx"]:
                pdf_path = self.convert_excel_to_pdf(file_path)
            elif file_extension == ".pptx":
                pdf_path = self.convert_ppt_to_pdf(file_path)
            else:
                return Response(
                    {"error": "Unsupported file type"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Extract text and return response
            parsed_text, num_pages, num_characters = self.extract_text_with_ocr(pdf_path)

            return Response(
                {
                    "numPages": num_pages,
                    "numCharacters": num_characters,
                    "parsedText": parsed_text,
                },
                status=status.HTTP_200_OK,
            )

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

        # Query the ContentVersion for the specified document
        query = f"SELECT VersionData, Title, FileExtension FROM ContentVersion WHERE Id = '{document_id}'"
        capture_message(f"Executing Salesforce Query: {query}", level="info")
        content_version = sf.query(query)

        if not content_version["records"]:
            raise ValueError(f"No file found for DocumentId {document_id}")

        # Fetch file metadata
        version_data_relative_url = content_version["records"][0]["VersionData"]
        capture_message(f"Fetching VersionData from URL: {version_data_url}", level="info")
        file_name = content_version["records"][0]["Title"]
        file_extension = content_version["records"][0]["FileExtension"]

        # Construct full URL to fetch the file
        version_data_url = f"{instance_url}/services/data/v{sf.sf_version}{version_data_relative_url}"
        capture_message(f"Fetching VersionData from URL: {version_data_url}", level="info")
        # Perform the request with Bearer token
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(version_data_url, headers=headers, stream=True)

        if response.status_code != 200:
            raise ValueError(f"Failed to fetch file content. HTTP Status {response.status_code}")

        # Save the file to a temporary location
        file_path = os.path.join(settings.MEDIA_ROOT, f"{file_name}.{file_extension}")
        with open(file_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=1024):
                f.write(chunk)

        return file_path

    def extract_text_with_ocr(self, pdf_path):
        """
        Extract text from PDF using OCR.
        """
        reader = PdfReader(pdf_path)
        text = ""
        num_pages = len(reader.pages)

        for page in reader.pages:
            extracted_text = page.extract_text()
            text += extracted_text if extracted_text else ""

        num_characters = len(text)
        return text, num_pages, num_characters

    def convert_image_to_pdf(self, image_path):
        pdf_path = f"{os.path.splitext(image_path)[0]}.pdf"
        images = convert_from_path(image_path)
        images[0].save(pdf_path, "PDF")
        return pdf_path

    def convert_docx_to_pdf(self, docx_path):
        pdf_path = f"{os.path.splitext(docx_path)[0]}.pdf"
        pdf = canvas.Canvas(pdf_path)
        document = Document(docx_path)
        text = "\n".join([p.text for p in document.paragraphs])
        pdf.drawString(100, 750, text)
        pdf.save()
        return pdf_path

    def convert_excel_to_pdf(self, excel_path):
        pdf_path = f"{os.path.splitext(excel_path)[0]}.pdf"
        workbook = load_workbook(excel_path)
        pdf = canvas.Canvas(pdf_path)

        y = 750
        margin = 50
        page_width = 595.27
        page_height = 841.89

        for sheet in workbook.sheetnames:
            worksheet = workbook[sheet]
            pdf.drawString(margin, y, f"Worksheet: {sheet}")
            y -= 20

            for row in worksheet.iter_rows(values_only=True):
                text = " | ".join([str(cell) if cell is not None else "" for cell in row])
                pdf.drawString(margin, y, text)
                y -= 20

                if y <= margin:
                    pdf.showPage()
                    y = page_height - margin

        pdf.save()
        return pdf_path

    def convert_ppt_to_pdf(self, ppt_path):
        pdf_path = f"{os.path.splitext(ppt_path)[0]}.pdf"
        presentation = Presentation(ppt_path)
        pdf = canvas.Canvas(pdf_path)
        y = 750
        for slide in presentation.slides:
            for shape in slide.shapes:
                if shape.has_text_frame:
                    text = shape.text
                    pdf.drawString(100, y, text)
                    y -= 20
        pdf.save()
        return pdf_path
