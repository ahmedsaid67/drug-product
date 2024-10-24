from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import CustomUser,Profile,Ilac,IlacKategori,HassasiyetTuru,Hastalik,\
    YasDoz,KiloDoz,ExplanationDoz,HatalikYasDoz,ArtanKiloDoz,HastalikKiloDoz,AzalanKiloDoz,\
    HastalikArtanKiloDoz,HastalikAzalanKiloDoz,HastalikHemYasaHemKiloyaBagliArtanDoz,\
    HastalikHemYasaHemKiloyaBagliAzalanDoz,Supplement,ProductCategory,Product,Hatirlatici,HatirlaticiSaati,Bildirim,Form

class UserAdmin(BaseUserAdmin):
    model = CustomUser
    list_display = ('email', 'first_name', 'last_name', 'is_staff', 'is_superuser')
    list_filter = ('is_staff', 'is_superuser')
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser')}),
    )
    add_fieldsets = (
        (None, {'classes': ('wide',), 'fields': ('email', 'first_name', 'last_name', 'password1', 'password2')}),
    )
    search_fields = ('email', 'first_name', 'last_name')
    ordering = ('email',)

admin.site.register(CustomUser, UserAdmin)
admin.site.register(Profile)
admin.site.register(Ilac)
admin.site.register(IlacKategori)
admin.site.register(HassasiyetTuru)
admin.site.register(Hastalik)
admin.site.register(Form)
admin.site.register(YasDoz)
admin.site.register(KiloDoz)
admin.site.register(ExplanationDoz)
admin.site.register(HatalikYasDoz)
admin.site.register(ArtanKiloDoz)
admin.site.register(HastalikKiloDoz)
admin.site.register(AzalanKiloDoz)
admin.site.register(HastalikArtanKiloDoz)
admin.site.register(HastalikAzalanKiloDoz)
admin.site.register(HastalikHemYasaHemKiloyaBagliArtanDoz)
admin.site.register(HastalikHemYasaHemKiloyaBagliAzalanDoz)
admin.site.register(Supplement)
admin.site.register(ProductCategory)
admin.site.register(Product)
admin.site.register(Hatirlatici)
admin.site.register(HatirlaticiSaati)
admin.site.register(Bildirim)

