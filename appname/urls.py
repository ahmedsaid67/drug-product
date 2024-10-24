from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import CustomAuthToken, CheckToken, UserInfoView, Logout,CustomUserViewSet,ProfilViewSet,PasswordResetViewSet,\
    GoogleLoginView,IlacKategoriViewSet,HassasiyetTuruViewSet,FormViewSet,IlacViewSet,HastalikViewSet,YasDozViewSet,KiloDozViewSet,\
    ExplanationDozViewSet,HatalikYasDozViewSet,HastalikKiloDozViewSet,ArtanKiloDozViewSet,AzalanKiloDozViewSet,\
    HastalikArtanKiloDozViewSet,HastalikAzalanKiloDozViewSet,HastalikHemYasaHemKiloyaBagliArtanDozViewSet,\
    HastalikHemYasaHemKiloyaBagliAzalanDozViewSet,SupplementViewSet,ProductCategoryViewSet,ProductViewSet,\
    CombinedView,HatirlaticiViewSet,HatirlaticiSaatiViewSet,BildirimViewSet

from django.conf import settings
from django.conf.urls.static import static


router_users = DefaultRouter()
router_users.register(r'users', CustomUserViewSet, basename='user')

router_profil = DefaultRouter()
router_profil.register(r'profils', ProfilViewSet, basename='profil')

router_reset = DefaultRouter()
router_reset.register(r'password-reset', PasswordResetViewSet, basename='password-reset')

router_ilackategori = DefaultRouter()
router_ilackategori.register(r'ilac-kategori', IlacKategoriViewSet)

router_hassasiyet_turu = DefaultRouter()
router_hassasiyet_turu.register(r'hassasiyet-turu', HassasiyetTuruViewSet)

router_hastalik = DefaultRouter()
router_hastalik.register(r'hastaliklar', HastalikViewSet)

router_form = DefaultRouter()
router_form.register(r'form', FormViewSet)

router_ilac = DefaultRouter()
router_ilac.register(r'ilac', IlacViewSet)

router_yasdoz = DefaultRouter()
router_yasdoz.register(r'yasdoz', YasDozViewSet)

router_kilodoz = DefaultRouter()
router_kilodoz.register(r'kilodoz', KiloDozViewSet)

router_explanationdoz = DefaultRouter()
router_explanationdoz.register(r'explanationdoz', ExplanationDozViewSet)

router_hastalikyasdoz = DefaultRouter()
router_hastalikyasdoz.register(r'hastalikyasdoz', HatalikYasDozViewSet)

router_hastalikkilodoz = DefaultRouter()
router_hastalikkilodoz.register(r'hastalikkilodoz', HastalikKiloDozViewSet)

router_artankilodoz = DefaultRouter()
router_artankilodoz.register(r'artankilodoz', ArtanKiloDozViewSet)

router_azalankilodoz = DefaultRouter()
router_azalankilodoz.register(r'azalankilodoz', AzalanKiloDozViewSet)

router_hastalikartankilodoz = DefaultRouter()
router_hastalikartankilodoz.register(r'hastalikartankilodoz', HastalikArtanKiloDozViewSet)

router_hastalikazalankilodoz = DefaultRouter()
router_hastalikazalankilodoz.register(r'hastalikazalankilodoz', HastalikAzalanKiloDozViewSet)

router_hastalikhemyasahemkiloyabagliartandoz = DefaultRouter()
router_hastalikhemyasahemkiloyabagliartandoz.register(r'hastalikhemyasahemkiloyabagliartandoz', HastalikHemYasaHemKiloyaBagliArtanDozViewSet)

router_hastalikhemyasahemkiloyabagliazalandoz = DefaultRouter()
router_hastalikhemyasahemkiloyabagliazalandoz.register(r'hastalikhemyasahemkiloyabagliazalandoz', HastalikHemYasaHemKiloyaBagliAzalanDozViewSet)

router_supplement = DefaultRouter()
router_supplement.register(r'supplements', SupplementViewSet)

router_productcategory = DefaultRouter()
router_productcategory.register(r'productcategory', ProductCategoryViewSet)

router_product = DefaultRouter()
router_product.register(r'products', ProductViewSet)

router_hatirlatici = DefaultRouter()
router_hatirlatici.register(r'reminders', HatirlaticiViewSet)

router_hatirlaticisaati = DefaultRouter()
router_hatirlaticisaati.register(r'reminder-hours', HatirlaticiSaatiViewSet)

router_bildirim = DefaultRouter()
router_bildirim.register(r'notifications', BildirimViewSet)


urlpatterns = [

    # auth apileri
    path('token/', CustomAuthToken.as_view(), name='api-token'),
    path('check-token/', CheckToken.as_view(), name='check-token'),
    path('user-info/', UserInfoView.as_view(), name='user-info'),
    path('logout/', Logout.as_view(), name='logout'),
    path('google/', GoogleLoginView.as_view(), name='google-login'),
    path('combined/', CombinedView.as_view(), name='combined-list'),
    path('', include(router_users.urls)),
    path('', include(router_profil.urls)),
    path('', include(router_reset.urls)),
    path('', include(router_ilackategori.urls)),
    path('', include(router_hassasiyet_turu.urls)),
    path('', include(router_hastalik.urls)),
    path('', include(router_form.urls)),
    path('', include(router_ilac.urls)),
    path('', include(router_yasdoz.urls)),
    path('', include(router_kilodoz.urls)),
    path('', include(router_explanationdoz.urls)),
    path('', include(router_hastalikyasdoz.urls)),
    path('', include(router_hastalikkilodoz.urls)),
    path('', include(router_artankilodoz.urls)),
    path('', include(router_azalankilodoz.urls)),
    path('', include(router_hastalikartankilodoz.urls)),
    path('', include(router_hastalikazalankilodoz.urls)),
    path('', include(router_hastalikhemyasahemkiloyabagliartandoz.urls)),
    path('', include(router_hastalikhemyasahemkiloyabagliazalandoz.urls)),
    path('', include(router_supplement.urls)),
    path('', include(router_productcategory.urls)),
    path('', include(router_product.urls)),

    path('', include(router_hatirlatici.urls)),
    path('', include(router_hatirlaticisaati.urls)),
    path('', include(router_bildirim.urls)),

]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)