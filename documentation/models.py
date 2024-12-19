from tinymce.models import HTMLField
from django.db import models

class DocumentationSection(models.Model):
    """
    Represents a section of the API documentation.
    """
    title = models.CharField(max_length=200, unique=True)
    slug = models.SlugField(unique=True)
    content = HTMLField()
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ['order']

    def __str__(self):
        return self.title
    
class ResponseCode(models.Model):
    """
    Represents a response code associated with a documentation section.
    """
    section = models.ForeignKey(DocumentationSection, on_delete=models.CASCADE, related_name="response_codes")
    code = models.PositiveIntegerField()
    description = models.TextField()

    class Meta:
        ordering = ['code']

    def __str__(self):
        return f"{self.code} - {self.description}"


class Example(models.Model):
    """
    Represents an example output for a specific response code.
    """
    response_code = models.ForeignKey(ResponseCode, on_delete=models.CASCADE, related_name="examples")
    example_text = models.TextField()

    def __str__(self):
        return f"Example for {self.response_code.code}"