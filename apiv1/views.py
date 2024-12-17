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


class DocumentProcessingView(APIView):
    authentication_classes = [CustomTokenAuthentication]
    permission_classes = [IsAuthenticated]
    def post(self, request):
        capture_message("DocumentProcessingView: API POST request received", level="info")
        session_id = request.data.get("sessionId")
        document_id = request.data.get("documentId")
        instance_url = request.data.get("instanceURL")

        if not session_id or not document_id or not instance_url:
            capture_message("Missing required parameters in request", level="warning")
            return Response(
                {"error": "Missing sessionId, documentId, or instanceURL"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        
        try:
            file_path = self.fetch_file_from_salesforce(
                session_id, document_id, instance_url
            )
            

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

    def extract_text_with_ocr(self, pdf_path):
        """
        Extract text using OCR for non-searchable PDFs.
        """
        reader = PdfReader(pdf_path)
        text = ""
        num_pages = len(reader.pages)

        for page in reader.pages:
            text += page.extract_text()

        # If text is empty, perform OCR
        #if not text.strip():
            # Specify Poppler path for Windows
            # poppler_path = r"C:\poppler\Library\bin"  # Update this path if necessary
            # images = convert_from_path(pdf_path, dpi=300, poppler_path=poppler_path)
            # ocr_text = [image_to_string(image, lang="eng") for image in images]
            # text = " ".join(ocr_text)

        # num_characters = len(text)
        return text, num_pages, 0

    def fetch_file_from_salesforce(self, session_id, document_id, instance_url):
        sf = Salesforce(instance_url=instance_url, session_id=session_id)

        content_version = sf.query(
            f"SELECT VersionData, Title, FileExtension FROM ContentVersion WHERE Id = '{document_id}'"
        )

        if not content_version["records"]:
            raise ValueError(f"No file found for DocumentId {document_id}")

        version_data_relative_url = content_version["records"][0]["VersionData"]
        file_name = content_version["records"][0]["Title"]
        file_extension = content_version["records"][0]["FileExtension"]

        version_data_url = f"{instance_url}{version_data_relative_url}"

        headers = {"Authorization": f"Bearer {session_id}"}
        response = requests.get(version_data_url, headers=headers, stream=True)

        if response.status_code != 200:
            raise ValueError(f"Failed to fetch file content. HTTP Status {response.status_code}")

        file_path = os.path.join(settings.MEDIA_ROOT, f"{file_name}.{file_extension}")
        with open(file_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=1024):
                f.write(chunk)

        return file_path

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
