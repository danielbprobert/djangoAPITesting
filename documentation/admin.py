from django.contrib import admin
from .models import DocumentationSection, ResponseCode, Example

class ExampleInline(admin.TabularInline):
    model = Example
    extra = 1

class ResponseCodeAdmin(admin.ModelAdmin):
    inlines = [ExampleInline]

admin.site.register(DocumentationSection)
admin.site.register(ResponseCode, ResponseCodeAdmin)