from django.shortcuts import render, get_object_or_404
from .models import DocumentationSection

def index(request):
    """
    Render the documentation homepage with a list of all sections.
    """
    sections = DocumentationSection.objects.all()
    return render(request, 'documentation/index.html', {
        'segment': 'documentation',
        'sections': sections,
    })

def section(request, slug):
    """
    Render a specific documentation section with response codes and examples.
    """
    section = get_object_or_404(DocumentationSection, slug=slug)
    response_codes = section.response_codes.prefetch_related('examples')
    sections = DocumentationSection.objects.all()  # For sidebar
    return render(request, 'documentation/section.html', {
        'segment': 'documentation',
        'section': section,
        'sections': sections,
        'response_codes': response_codes,
    })