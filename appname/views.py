from django.shortcuts import render
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken,ObtainEmailAuthToken
from rest_framework.views import APIView
from .serializers import CustomUserSerializer,ProfileSerilizers
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from .models import Profile


User = get_user_model()

# Your existing views remain unchanged
class CustomAuthToken(ObtainEmailAuthToken):
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            print("Validation errors:", serializer.errors)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        # Kullanıcı bilgilerini döndürmek için serializer kullan
        user_serializer = CustomUserSerializer(user)

        return Response({
            'token': token.key,
            'user': user_serializer.data  # Tüm kullanıcı bilgileri
        })



class CheckToken(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({'message': 'Token is valid'})

class Logout(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            token = request.auth
            Token.objects.filter(key=token).delete()
            return Response({"message": "Successfully logged out"}, status=status.HTTP_200_OK)
        except:
            return Response({"error": "Something went wrong"}, status=status.HTTP_400_BAD_REQUEST)

class UserInfoView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        user = request.user
        serializer = CustomUserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)



class CustomUserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = CustomUserSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # Kullanıcıya ait token'ı oluştur
        token, created = Token.objects.get_or_create(user=user)

        user_serializer = CustomUserSerializer(user)

        return Response({
            'token': token.key,
            'user': user_serializer.data  # Tüm kullanıcı bilgileri
        })


class ProfilViewSet(viewsets.ModelViewSet):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerilizers


    @action(detail=False, methods=['get'], url_path='get_profile_by_user_id/(?P<user_id>\d+)')
    def get_profile_by_user_id(self, request, user_id=None):
            try:
                profile = Profile.objects.get(user__id=user_id)
            except Profile.DoesNotExist:
                return Response({"detail": "Profile not found for this user."}, status=status.HTTP_404_NOT_FOUND)

            serializer = self.get_serializer(profile)
            return Response(serializer.data, status=status.HTTP_200_OK)

        # PUT method for updating a profile by user_id
    @action(detail=False, methods=['put'], url_path='update_profile_by_user_id/(?P<user_id>\d+)')
    def update_profile_by_user_id(self, request, user_id=None):
            try:
                profile = Profile.objects.get(user__id=user_id)
            except Profile.DoesNotExist:
                return Response({"detail": "Profile not found for this user."}, status=status.HTTP_404_NOT_FOUND)

            serializer = self.get_serializer(profile, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




from datetime import timedelta

from django.core.mail import send_mail
from django.utils import timezone
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from .models import PasswordResetCode, CustomUser
import random
from django.conf import settings

from django.core.validators import validate_email
from django.core.exceptions import ValidationError


class PasswordResetViewSet(viewsets.GenericViewSet):
    @action(detail=False, methods=['post'], url_path='request-reset')
    def request_reset(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'email': ['E-posta gerekli.']}, status=status.HTTP_400_BAD_REQUEST)

        # Validate email format
        try:
            validate_email(email)
        except ValidationError:
            return Response({'email': ['Geçerli bir e-posta adresi girin.']}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return Response({'email': ['Bu e-posta adresine sahip bir kullanıcı bulunamadı.']},
                            status=status.HTTP_404_NOT_FOUND)

        code = '{:06d}'.format(random.randint(0, 999999))  # 6 haneli kod oluşturma
        PasswordResetCode.objects.create(
            user=user,
            code=code,
            expires_at=timezone.now() + timedelta(minutes=15)
        )

        email_body = f"""
        <div style="font-family: Arial, sans-serif; color: #14171a; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #eaeaea; border-radius: 8px; background-color: #f9f9f9;">
            <h2 style="text-align: center; color: #1D64F2;">Ölçek - Şifre Sıfırlama</h2>
            <p style="font-size: 16px; color: #14171a;">Merhaba,</p>
            <p style="font-size: 16px; color: #14171a;">Şifrenizi sıfırlamak için aşağıdaki kodu kullanın:</p>
            <p style="font-size: 24px; font-weight: bold; text-align: center; padding: 10px; background-color: #E7F3FE; border: 1px solid #1D64F2; border-radius: 4px; color: #1D64F2;">{code}</p>
            <p style="font-size: 16px; color: #14171a;">Eğer bu işlemi siz yapmadıysanız, bu e-postayı dikkate almayın.</p>
            <p style="font-size: 16px; color: #14171a;">Teşekkürler,<br>Ölçek Destek Ekibi</p>
            <hr style="border: 0; border-top: 1px solid #eaeaea; margin: 20px 0;">
            <p style="font-size: 12px; text-align: center; color: #999;">Bu e-posta, Ölçek uygulamasından bir şifre sıfırlama isteğiyle ilgili gönderilmiştir.</p>
        </div>
        """

        send_mail(
            'Şifre Sıfırlama İsteği',
            '',
            settings.DEFAULT_FROM_EMAIL,
            [email],
            html_message=email_body
        )

        return Response({'detail': 'Şifre sıfırlama kodu e-posta adresinize gönderildi.'}, status=status.HTTP_200_OK)

    @action(detail=False, methods=['post'], url_path='reset-password')
    def reset_password(self, request):
        code = request.data.get('code')
        new_password = request.data.get('new_password')

        if not code or not new_password:
            return Response({'detail': 'Code and new password are required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            reset_code = PasswordResetCode.objects.get(code=code)
        except PasswordResetCode.DoesNotExist:
            return Response({'detail': 'Invalid or expired code.'}, status=status.HTTP_400_BAD_REQUEST)

        if not reset_code.is_valid():
            return Response({'detail': 'Code has expired.'}, status=status.HTTP_400_BAD_REQUEST)

        user = reset_code.user
        user.set_password(new_password)
        user.save()

        # Code is used, so we delete it
        reset_code.delete()

        return Response({'detail': 'Password has been reset successfully.'}, status=status.HTTP_200_OK)



import google.oauth2.id_token
import google.auth.transport.requests
from django.db import transaction





class GoogleLoginView(APIView):
    def post(self, request, *args, **kwargs):
        id_token_received = request.data.get('token')
        if not id_token_received:
            print("Token sağlanmadı")
            return Response({'error': 'Token sağlanmadı'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Google token'ını doğrula
            idinfo = google.oauth2.id_token.verify_oauth2_token(
                id_token_received,
                google.auth.transport.requests.Request(),
                settings.GOOGLE_CLIENT_ID
            )

            # Google kullanıcı bilgilerini al
            email = idinfo.get('email')
            if not email:
                raise KeyError('email')

            first_name = idinfo.get('given_name', '')
            last_name = idinfo.get('family_name', '')

            with transaction.atomic():
                # Kullanıcıyı bul
                user = User.objects.filter(email=email).first()

                if user is None:
                    # Kullanıcı yoksa, bilgileri al ve yeni kullanıcıyı oluştur
                    user = User(email=email, first_name=first_name, last_name=last_name)
                    user.set_unusable_password()  # Google OAuth ile şifre belirlenmez
                    user.save()
                    is_new_user = True
                else:
                    # Kullanıcı varsa, last_name ve first_name kontrolü
                    if first_name:
                        user.first_name = first_name
                    if last_name:
                        user.last_name = last_name
                    user.save()
                    is_new_user = False

                # Token üret
                token, _ = Token.objects.get_or_create(user=user)
                return Response({'token': token.key, 'is_new_user': is_new_user}, status=status.HTTP_200_OK)

        except ValueError as e:
            return Response({'error': 'Geçersiz token: ' + str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except KeyError as e:
            if str(e) == 'email':
                return Response({'error': 'Google tokenında email bilgisi mevcut değil.'}, status=status.HTTP_400_BAD_REQUEST)
            return Response({'error': 'Google tokenında eksik bilgi: ' + str(e)}, status=status.HTTP_400_BAD_REQUEST)




# ------ ilaç -------

from rest_framework.pagination import PageNumberPagination

class NoPagination(PageNumberPagination):
    page_size = None
    page_size_query_param = None
    max_page_size = None

from .models import IlacKategori
from .serializers import IlacKategoriSerializers
import pandas as pd

class IlacKategoriViewSet(viewsets.ModelViewSet):
    queryset = IlacKategori.objects.all()
    serializer_class = IlacKategoriSerializers
    pagination_class = NoPagination

    @action(detail=False, methods=['post'])
    def bulk_create_from_excel(self, request):
        file = request.FILES.get('file')
        if not file:
            return Response({'error': 'No file uploaded'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Read the uploaded Excel file
            df = pd.read_excel(file)

            # Check if required columns exist
            if 'name' not in df.columns or 'durum' not in df.columns:
                return Response({'error': 'Excel file must contain "name" and "durum" columns'},
                                status=status.HTTP_400_BAD_REQUEST)

            # Clean and validate data
            df_filtered = df[df['durum'] == False]  # Filter rows where 'durum' is False

            # Extract unique names
            names = df_filtered['name'].dropna().str.strip().unique()


            # Check existing categories in the database
            existing_categories = set(IlacKategori.objects.filter(name__in=names).values_list('name', flat=True))

            # Create new `IlacKategori` instances for names not already in the database
            new_names = [name for name in names if name not in existing_categories]
            categories = [IlacKategori(name=name) for name in new_names]
            IlacKategori.objects.bulk_create(categories)

            return Response({'status': 'Categories created successfully'}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({'error': f'An error occurred while processing the file: {str(e)}'},
                            status=status.HTTP_400_BAD_REQUEST)


from .models import HassasiyetTuru
from .serializers import HassasiyetTuruSerializers


class HassasiyetTuruViewSet(viewsets.ModelViewSet):
    queryset = HassasiyetTuru.objects.all()
    serializer_class = HassasiyetTuruSerializers
    pagination_class = NoPagination

    @action(detail=False, methods=['post'])
    def bulk_create_from_excel(self, request):
        file = request.FILES.get('file')
        if not file:
            return Response({'error': 'No file uploaded'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Read the uploaded Excel file
            df = pd.read_excel(file)

            # Check if required columns exist
            if 'name' not in df.columns or 'durum' not in df.columns:
                return Response({'error': 'Excel file must contain "name" and "durum" columns'},
                                status=status.HTTP_400_BAD_REQUEST)

            # Clean and validate data
            df_filtered = df[df['durum'] == False]  # Filter rows where 'durum' is False

            # Extract unique names
            names = df_filtered['name'].dropna().str.strip().unique()

            # Check existing categories in the database
            existing_categories = set(HassasiyetTuru.objects.filter(name__in=names).values_list('name', flat=True))

            # Create new `IlacKategori` instances for names not already in the database
            new_names = [name for name in names if name not in existing_categories]
            categories = [HassasiyetTuru(name=name) for name in new_names]
            HassasiyetTuru.objects.bulk_create(categories)

            return Response({'status': 'Categories created successfully'}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({'error': f'An error occurred while processing the file: {str(e)}'},
                            status=status.HTTP_400_BAD_REQUEST)




from .models import Hastalik
from .serializers import HastalikSerializers


class HastalikViewSet(viewsets.ModelViewSet):
    queryset = Hastalik.objects.all()
    serializer_class = HastalikSerializers
    pagination_class = NoPagination

    @action(detail=False, methods=['post'])
    def bulk_create_from_excel(self, request):
        file = request.FILES.get('file')
        if not file:
            return Response({'error': 'No file uploaded'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Read the uploaded Excel file
            df = pd.read_excel(file)

            # Check if required columns exist
            if 'name' not in df.columns or 'durum' not in df.columns:
                return Response({'error': 'Excel file must contain "name" and "durum" columns'},
                                status=status.HTTP_400_BAD_REQUEST)

            # Clean and validate data
            df_filtered = df[df['durum'] == False]  # Filter rows where 'durum' is False

            # Extract unique names
            names = df_filtered['name'].dropna().str.strip().unique()

            # Check existing categories in the database
            existing_categories = set(Hastalik.objects.filter(name__in=names).values_list('name', flat=True))

            # Create new `IlacKategori` instances for names not already in the database
            new_names = [name for name in names if name not in existing_categories]
            categories = [Hastalik(name=name) for name in new_names]
            Hastalik.objects.bulk_create(categories)

            return Response({'status': 'Categories created successfully'}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({'error': f'An error occurred while processing the file: {str(e)}'},
                            status=status.HTTP_400_BAD_REQUEST)



from .models import Form
from .serializers import FormSerializers


class FormViewSet(viewsets.ModelViewSet):
    queryset = Form.objects.all().order_by('name')
    serializer_class = FormSerializers
    pagination_class = NoPagination

    @action(detail=False, methods=['post'])
    def bulk_create_from_excel(self, request):
        file = request.FILES.get('file')
        if not file:
            return Response({'error': 'No file uploaded'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Read the uploaded Excel file
            df = pd.read_excel(file)

            # Check if required columns exist
            if 'name' not in df.columns or 'durum' not in df.columns:
                return Response({'error': 'Excel file must contain "name" and "durum" columns'},
                                status=status.HTTP_400_BAD_REQUEST)

            # Clean and validate data
            df_filtered = df[df['durum'] == False]  # Filter rows where 'durum' is False

            # Extract unique names
            names = df_filtered['name'].dropna().str.strip().unique()

            # Check existing categories in the database
            existing_categories = set(Form.objects.filter(name__in=names).values_list('name', flat=True))

            # Create new `IlacKategori` instances for names not already in the database
            new_names = [name for name in names if name not in existing_categories]
            categories = [Form(name=name) for name in new_names]
            Form.objects.bulk_create(categories)

            return Response({'status': 'Categories created successfully'}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({'error': f'An error occurred while processing the file: {str(e)}'},
                            status=status.HTTP_400_BAD_REQUEST)



from .models import Ilac
from .serializers import IlacListSerializer,IlacDetailSerializer

class IlacViewSet(viewsets.ModelViewSet):
    queryset = Ilac.objects.all().select_related('ilac_kategori', 'hassasiyet_turu','ilac_form').prefetch_related('hastaliklar').order_by('id')

    def get_serializer_class(self):
        if self.action in ['list', 'medications_by_category', 'medications_by_category_no_pagination','medications-by-form-no-pagination']:
            return IlacListSerializer
        return IlacDetailSerializer

    def get_queryset(self):
        # List işlemi için optimize edilmiş queryset (kategori ve hastalıklar dahil değil)
        if self.action == 'list':
            return Ilac.objects.only('id', 'name', 'etken_madde', 'hassasiyet_turu').select_related(
                'hassasiyet_turu').order_by('id')
        # Diğer işlemler için tam queryset
        return Ilac.objects.select_related('ilac_kategori', 'hassasiyet_turu', 'hassasiyet_turu','ilac_form').prefetch_related('hastaliklar').order_by(
            'id')

    @action(detail=False, methods=['get'], url_path='medications-by-category')
    def medications_by_category(self, request):
        category_id = request.query_params.get('category_id')
        if not category_id:
            return Response(
                {"detail": "category_id parameter is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # İlaçları kategoriye göre filtrele, values() kaldırıldı
        medications = Ilac.objects.filter(ilac_kategori_id=category_id).only('id', 'name', 'etken_madde', 'hassasiyet_turu').select_related('hassasiyet_turu').order_by('id')

        # Sorguyu sayfalı hale getirmek
        page = self.paginate_queryset(medications)
        if page is not None:
            # Sayfalı veriyi serialize et
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        # Sayfalama yoksa tüm veriyi döndür
        serializer = self.get_serializer(medications, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'], url_path='medications-by-category-no-pagination')
    def medications_by_category_no_pagination(self, request):
        category_id = request.query_params.get('category_id')
        if not category_id:
            return Response(
                {"detail": "category_id parameter is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # İlaçları kategoriye göre filtrele, values() kaldırıldı
        medications = Ilac.objects.filter(ilac_kategori_id=category_id).only('id', 'name', 'etken_madde', 'hassasiyet_turu').select_related('hassasiyet_turu').order_by('id')

        # Sayfalama olmadan veriyi serialize et ve döndür
        serializer = self.get_serializer(medications, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'], url_path='medications-by-form-no-pagination')
    def medications_by_form_no_pagination(self, request):
        form_id = request.query_params.get('form_id')
        if not form_id:
            return Response(
                {"detail": "category_id parameter is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # İlaçları kategoriye göre filtrele, values() kaldırıldı
        medications = Ilac.objects.filter(ilac_form_id=form_id).only('id', 'name', 'etken_madde','hassasiyet_turu').select_related('hassasiyet_turu').order_by('id')

        # Sayfalama olmadan veriyi serialize et ve döndür
        serializer = IlacListSerializer(medications, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'], url_path='medications-by-form')
    def medications_by_form(self, request):
        form_id = request.query_params.get('form_id')
        if not form_id:
            return Response(
                {"detail": "category_id parameter is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # İlaçları kategoriye göre filtrele, values() kaldırıldı
        medications = Ilac.objects.filter(ilac_form_id=form_id).only('id', 'name', 'etken_madde','hassasiyet_turu').select_related('hassasiyet_turu').order_by('id')

        # Sorguyu sayfalı hale getirmek
        page = self.paginate_queryset(medications)
        if page is not None:
            # Sayfalı veriyi serialize et
            serializer = IlacListSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        # Sayfalama yoksa tüm veriyi döndür
        serializer = IlacListSerializer(medications, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['post'])
    def bulk_create_from_excel(self, request):
        file = request.FILES.get('file')
        if not file:
            return Response({'error': 'No file uploaded. Please upload a valid Excel file.'},
                            status=status.HTTP_400_BAD_REQUEST)

        try:
            # Excel dosyasını oku
            df = pd.read_excel(file)

            # Gerekli sütunlar kontrolü
            required_columns = ['name', 'durum', 'etken madde', 'ilaç kategori', 'Kullanım Uyarı', 'hassasiyet türü',
                                'ilaç form', 'hastalıklar', 'Konsantrasyon ml', 'Konsantrasyon mg']
            missing_columns = [col for col in required_columns if col not in df.columns]
            if missing_columns:
                return Response(
                    {'error': f'Excel file is missing the following required columns: {", ".join(missing_columns)}'},
                    status=status.HTTP_400_BAD_REQUEST)

            # Yeni ilaçlar listesi
            new_ilac_list = []
            for _, row in df.iterrows():
                # Eğer durum True ise devam et (zaten oluşturulmuşsa)

                isim = row['name']
                if row['durum'] == True or pd.isna(isim):
                    continue

                kategori = row.get('ilaç kategori', '')
                if not pd.isna(kategori):
                    ilac_kategori = IlacKategori.objects.filter(id=row['ilaç kategori']).first()
                else:
                    ilac_kategori=None

                kategori_form = row.get('ilaç form', '')
                if not pd.isna(kategori_form):
                    ilac_form = Form.objects.filter(id=row['ilaç form']).first()
                else:
                    ilac_form=None

                kategori_tur = row.get('hassasiyet türü', '')
                if not pd.isna(kategori_tur):
                    hassasiyet_turu = HassasiyetTuru.objects.filter(id=row['hassasiyet türü']).first()
                else:
                    hassasiyet_turu = None




                # Kullanım Uyarısı alanı boşsa veya NaN ise, boş string ile değiştir
                kullanim_uyarisi = row.get('Kullanım Uyarı', '')
                if pd.isna(kullanim_uyarisi):
                    kullanim_uyarisi = ''

                # Konsantrasyon değerleri NaN mı kontrol et
                konsantrasyon_ml = row['Konsantrasyon ml']
                konsantrasyon_mg = row['Konsantrasyon mg']
                if pd.isna(konsantrasyon_ml) or pd.isna(konsantrasyon_mg):
                    konsantrasyon_ml = None
                    konsantrasyon_mg = None

                # Yeni ilaç nesnesi oluştur
                new_ilac = Ilac(
                    name=row['name'],
                    ilac_form=ilac_form,
                    etken_madde=row['etken madde'],
                    ilac_kategori=ilac_kategori,
                    hassasiyet_turu=hassasiyet_turu,
                    kontsantrasyon_ml=konsantrasyon_ml,
                    kontsantrasyon_mg=konsantrasyon_mg,
                    kullanim_uyarisi=kullanim_uyarisi
                )
                new_ilac.save()  # Önce kaydetmemiz gerekiyor ki ManyToMany alanına hastalıkları ekleyebilelim

                # Hastalıklar alanı boş olabilir
                if pd.notna(row['hastalıklar']) and row['hastalıklar'].strip():
                    # Hastalık ID'lerini ayır ve ilgili Hastalik nesnelerini bul
                    hastalik_id_list = row['hastalıklar'].strip(
                        '[]').split()  # Köşeli parantezleri kaldırıp boşluk ile ayır
                    for hastalik_id in hastalik_id_list:
                        hastalik = Hastalik.objects.filter(id=hastalik_id).first()
                        if hastalik:
                            new_ilac.hastaliklar.add(hastalik)

                new_ilac_list.append(new_ilac)

            return Response({'status': 'Ilac records created successfully', 'records_created': len(new_ilac_list)},
                            status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({'error': f'An error occurred while processing the file: {str(e)}'},
                            status=status.HTTP_400_BAD_REQUEST)


from .models import YasDoz
from .serializers import YasDozSerializers,YasDozDetailSerializers

class YasDozViewSet(viewsets.ModelViewSet):
    queryset = YasDoz.objects.all().order_by('id')

    def get_serializer_class(self):
        # List için hafif serializer, detay için tam serializer
        if self.action == 'get_dosage_by_age':
            return YasDozDetailSerializers
        return YasDozSerializers

    @action(detail=False, methods=['get'], url_path='get-dosage-by-age')
    def get_dosage_by_age(self, request):
        # İlac ID ve yaş bilgilerini alıyoruz
        ilac_id = request.query_params.get('ilac_id')
        yas = int(request.query_params.get('yas', 0))
        yas_birimi = request.query_params.get('yas_birimi', 'yil')  # Default olarak 'yil'

        # Yaşı aya çevirme (Eğer yıl verilmişse)
        if yas_birimi == 'yil':
            yas *= 12  # Yılı aya çeviriyoruz

        # İlac ID ve yaşa göre filtreleme
        try:
            yas_doz = YasDoz.objects.get(ilac_id=ilac_id, min_yas__lte=yas, maks_yas__gte=yas)
            serializer = self.get_serializer(yas_doz)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except YasDoz.DoesNotExist:
            return Response({"detail": "Uygun dozaj bulunamadı."}, status=status.HTTP_404_NOT_FOUND)


    @action(detail=False, methods=['post'])
    def bulk_create_from_excel(self, request):
        file = request.FILES.get('file')
        if not file:
            return Response({'error': 'No file uploaded'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Read the uploaded Excel file
            df = pd.read_excel(file)

            # Correct column names pattern based on your provided Excel structure
            age_columns = [i for i in range(13)] + [i * 12 for i in
                                                    range(2, 20)]  # ['0', '1', ..., '12', '24', ..., '228']
            required_columns = ['İLAÇ AD', 'durum'] + age_columns + ['Yüksek Yaş Sınırı', 'Yüksek Yaş Sınırı Sonrası Uyarı']

            if not all(column in df.columns for column in required_columns):
                return Response({'error': 'Excel file is missing required columns.'},
                                status=status.HTTP_400_BAD_REQUEST)

            yas_doz_objects = []

            # Iterate through each row in the DataFrame
            for index, row in df.iterrows():
                # Only process rows where 'durum' is False
                if not row['durum']:
                    try:
                        # Fetch the Ilac object using 'ILAC ID'
                        ilac = Ilac.objects.get(name=row['İLAÇ AD'])

                        # Track the current dosage value and age range
                        current_doz = None
                        min_yas = 0

                        # Iterate through the age columns in the corrected order
                        for age_str in age_columns:
                            doz = row[age_str]

                            # If the dosage changes or we reach the last age column
                            if doz != current_doz or age_str == age_columns[-1]:
                                if current_doz is not None:
                                    # Create a YasDoz object for the previous age range
                                    maks_yas = int(age_str) - 1 if age_str != age_columns[-1] else int(age_str)
                                    yas_doz_objects.append(
                                        YasDoz(
                                            ilac=ilac,
                                            doz=current_doz,
                                            min_yas=min_yas,
                                            maks_yas=maks_yas,
                                        )
                                    )
                                # Update current dosage and reset min_yas
                                current_doz = doz
                                min_yas = int(age_str)

                        # Handle the final dosage range (from 228 to Yüksek Yaş using 228's dose)
                        if 'Yüksek Yaş Sınırı' in row and 'Yüksek Yaş Sınırı Sonrası Uyarı' in row:
                            yas_doz_objects.append(
                                YasDoz(
                                    ilac=ilac,
                                    doz=row[228],  # Use the dosage value from age 228
                                    min_yas=228,
                                    maks_yas=row['Yüksek Yaş Sınırı'],  # Set the 'maks_yas' to 'Yüksek Yaş'
                                )
                            )

                            # Handle the dosage for ages greater than "Yüksek Yaş"
                            if pd.notna(row['Yüksek Yaş Sınırı Sonrası Uyarı']):
                                # Handle the dosage for ages greater than "Yüksek Yaş"
                                yas_doz_objects.append(
                                    YasDoz(
                                        ilac=ilac,
                                        doz=row['Yüksek Yaş Sınırı Sonrası Uyarı'],
                                        # Use the 'Yas uyarı' value for dosage
                                        min_yas=row['Yüksek Yaş Sınırı'] + 1,
                                        # Set min_yas to one more than 'Yüksek Yaş'
                                        maks_yas=9999,
                                        # Use a large integer value to represent ages beyond "Yüksek Yaş"
                                    )
                                )

                    except Ilac.DoesNotExist:
                        return Response({'error': f'Ilac with ID {row["ILAC AD"]} not found.'},
                                        status=status.HTTP_400_BAD_REQUEST)

            # Perform bulk creation of YasDoz objects
            if yas_doz_objects:
                with transaction.atomic():
                    YasDoz.objects.bulk_create(yas_doz_objects)
                return Response({"message": f"{len(yas_doz_objects)} records created successfully."},
                                status=status.HTTP_201_CREATED)
            else:
                return Response({"message": "No records to create."}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



from .models import KiloDoz
from .serializers import KiloDozSerializers
from decimal import Decimal, ROUND_HALF_UP


class BaseOlcekHesaplayici:

    KASIK_OLCEGI_ML = Decimal('5')

    SPOON_ACCOUNTING_CATEGORIES = [1,5,6,7,17,18,29,30,31,35,45,2,3,19,32,27]

    def olcek_formatla(self, olcek_sayisi):
        tam_olcek = int(olcek_sayisi)
        kalan = olcek_sayisi - tam_olcek

        if tam_olcek == 0:
            if kalan >= Decimal('0.875') and kalan < Decimal('1'):
                return "1 ölçek"
            elif kalan > Decimal('0.75') and kalan < Decimal('0.875'):
                return "3/4 ölçek"
            elif kalan == Decimal('0.75'):
                return "3/4 ölçek"
            elif kalan >= Decimal('0.625') and kalan < Decimal('0.75'):
                return "3/4 ölçek"
            elif kalan > Decimal('0.50') and kalan < Decimal('0.625'):
                return "1/2 ölçek"
            elif kalan == Decimal('0.50'):
                return "1/2 ölçek"
            elif kalan >= Decimal('0.375') and kalan < Decimal('0.50'):
                return "1/2 ölçek"
            elif kalan > Decimal('0.25') and kalan < Decimal('0.375'):
                return "1/4 ölçek"
            elif kalan == Decimal('0.25'):
                return "1/4 ölçek"
            elif kalan >= Decimal('0.125') and kalan < Decimal('0.25'):
                return "1/4 ölçek"
            elif kalan > Decimal('0') and kalan < Decimal('0.125'):
                return "1/4 ölçek"
            else:
                return "0 ölçek"
        else:
            if kalan >= Decimal('0.875') and kalan < Decimal('1'):
                return f"{tam_olcek + 1}  ölçek"
            elif kalan > Decimal('0.75') and kalan < Decimal('0.875'):
                return f"{tam_olcek} + 3/4 ölçek"
            elif kalan == Decimal('0.75'):
                return f"{tam_olcek} + 3/4 ölçek"
            elif kalan >= Decimal('0.625') and kalan < Decimal('0.75'):
                return f"{tam_olcek} + 3/4 ölçek"
            elif kalan > Decimal('0.50') and kalan < Decimal('0.625'):
                return f"{tam_olcek} + 1/2 ölçek"
            elif kalan == Decimal('0.50'):
                return f"{tam_olcek} + 1/2 ölçek"
            elif kalan >= Decimal('0.375') and kalan < Decimal('0.50'):
                return f"{tam_olcek} + 1/2 ölçek"
            elif kalan > Decimal('0.25') and kalan < Decimal('0.375'):
                return f"{tam_olcek} + 1/4 ölçek"
            elif kalan == Decimal('0.25'):
                return f"{tam_olcek} + 1/4 ölçek"
            elif kalan >= Decimal('0.125') and kalan < Decimal('0.25'):
                return f"{tam_olcek} + 1/4 ölçek"
            elif kalan > Decimal('0') and kalan < Decimal('0.125'):
                return f"{tam_olcek} ölçek"
            else:
                return f"{tam_olcek} ölçek"


class KiloDozViewSet(viewsets.ModelViewSet, BaseOlcekHesaplayici):
    queryset = KiloDoz.objects.all().order_by('id')
    serializer_class = KiloDozSerializers


    @action(detail=False, methods=['get'], url_path='get-dosage-by-weight')
    def get_dosage_by_weight(self, request):
        kilo = request.query_params.get('kilo')
        ilac_id = request.query_params.get('ilac_id')

        if not kilo:
            return Response({'error': 'Kilo değeri sağlanmadı'}, status=status.HTTP_400_BAD_REQUEST)

        if not ilac_id:
            return Response({'error': 'İlaç ID değeri sağlanmadı'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            kilodoz = KiloDoz.objects.get(ilac_id=ilac_id)
        except KiloDoz.DoesNotExist:
            return Response({'error': 'Kilo doz bilgisi bulunamadı'}, status=status.HTTP_404_NOT_FOUND)

        tipik_min_doz = kilodoz.tipik_min_doz or Decimal('0')
        tipik_max_doz = kilodoz.tipik_max_doz or None  # Değeri None olarak ayarla
        maksimum_anlik_doz = kilodoz.maksimum_anlik_doz or Decimal('0')

        try:
            kilo = Decimal(str(kilo))
        except ValueError:
            return Response({'error': 'Kilo değeri geçersiz'}, status=status.HTTP_400_BAD_REQUEST)

        # Minimum doz hesaplama
        min_doz = kilo * tipik_min_doz

        if tipik_max_doz is None:
            # `tipik_max_doz` değeri yoksa sadece minimum doz üzerinden hesapla
            if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                min_kasik = (min_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                min_kasik_mesaj = self.olcek_formatla(min_kasik)
                doz_message = f"{min_kasik_mesaj} kullanın."
            else:
                doz_message = f"{min_doz} ml kullanın."


        else:
            # `tipik_max_doz` mevcutsa maksimum doz hesaplama
            maks_doz = kilo * tipik_max_doz

            # Eğer minimum doz veya maksimum doz, maksimum anlık dozu geçiyorsa
            if min_doz > maksimum_anlik_doz or maks_doz > maksimum_anlik_doz:
                # Maksimum anlık doza göre hesapla
                if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                    maks_kasik = (maksimum_anlik_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'),
                                                                                      rounding=ROUND_HALF_UP)
                    maks_kasik_mesaj = self.olcek_formatla(maks_kasik)
                    doz_message = f"{maks_kasik_mesaj} kullanın."
                else:
                    doz_message = f"{maksimum_anlik_doz} ml kullanın."
            else:
                if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                    # Kaşık ölçüsüne göre min doz hesaplama
                    min_kasik = (min_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                    min_kasik_mesaj = self.olcek_formatla(min_kasik)

                    # Maksimum doz hesaplama
                    maks_kasik = (maks_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                    maks_kasik_mesaj = self.olcek_formatla(maks_kasik)

                    # Eğer minimum ve maksimum ölçü aynıysa, tek mesaj göster
                    if min_kasik_mesaj == maks_kasik_mesaj:
                        doz_message = f"{min_kasik_mesaj} kullanın."
                    else:
                        doz_message = f"{min_kasik_mesaj} veya {maks_kasik_mesaj} kullanın."
                else:
                    doz_message = f"{min_doz} ml  veya {maks_doz} ml kullanın."

        # Kullanıcıya sunulacak ek bilgiler
        response_data = {
            'message': doz_message,
            'kullanim_sikligi': kilodoz.kullanim_sikligi,
            'check_uyari': kilodoz.check_uyari,
            'maksimum_anlik_doz': kilodoz.maksimum_anlik_doz,
        }

        return Response(response_data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['post'])
    def bulk_create_from_excel(self, request):
        file = request.FILES.get('file')
        if not file:
            return Response({'error': 'No file uploaded'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Excel dosyasını oku
            df = pd.read_excel(file)

            # Gerekli sütunların mevcut olup olmadığını kontrol et
            required_columns = ['İLAÇ AD', 'durum', 'Kullanım sıklığı', 'Check Uyarı',
                                'TİPİK MİN DOZ', 'TİPİK MAX DOZ', 'Maksimum anlık']
            if not all(column in df.columns for column in required_columns):
                return Response({
                    'error': 'Excel file must contain all required columns'
                }, status=status.HTTP_400_BAD_REQUEST)

            for _, row in df.iterrows():
                # Eğer 'durum' True ise (zaten işlenmiş), atla
                if row['durum'] == True:
                    continue

                try:
                    # İlgili Ilac nesnesini bul
                    ilac = Ilac.objects.get(name=row['İLAÇ AD'])

                    # Konsantrasyon oranını hesapla
                    kontsantrasyon_orani = ilac.kontsantrasyon_mg / ilac.kontsantrasyon_ml



                    # Alanları kontrol et ve uygun şekilde işle
                    # Tipik min doz hesabı
                    tipik_min_doz = row['TİPİK MİN DOZ'] if pd.notna(row['TİPİK MİN DOZ']) else None
                    if tipik_min_doz is not None:
                        tipik_min_doz = Decimal(tipik_min_doz) / kontsantrasyon_orani

                    # Tipik max doz hesabı
                    tipik_max_doz = row['TİPİK MAX DOZ'] if pd.notna(row['TİPİK MAX DOZ']) else None
                    if tipik_max_doz is not None:
                        tipik_max_doz = Decimal(tipik_max_doz) / kontsantrasyon_orani

                    # Maksimum anlık doz hesabı
                    maksimum_anlik_doz = row['Maksimum anlık'] if pd.notna(row['Maksimum anlık']) else None
                    if maksimum_anlik_doz is not None:
                        maksimum_anlik_doz = Decimal(maksimum_anlik_doz) / kontsantrasyon_orani


                    check_uyari = row.get('Check Uyarı', '')
                    if pd.isna(check_uyari):
                        check_uyari = ''

                    # Yeni KiloDoz nesnesi oluştur
                    new_ilac = KiloDoz(
                        kullanim_sikligi=row['Kullanım sıklığı'],
                        ilac=ilac,
                        check_uyari=check_uyari,
                        tipik_min_doz=tipik_min_doz,
                        tipik_max_doz=tipik_max_doz,
                        maksimum_anlik_doz=maksimum_anlik_doz,
                    )

                    # Yeni nesneyi kaydet
                    new_ilac.save()

                except Ilac.DoesNotExist:
                    return Response({'error': f'Ilac with ID {row["ILAC ID"]} not found.'},
                                    status=status.HTTP_400_BAD_REQUEST)

            return Response({'status': 'Ilac records created successfully'}, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({'error': f'An error occurred while processing the file: {str(e)}'},
                            status=status.HTTP_400_BAD_REQUEST)


from .models import ExplanationDoz
from .serializers import ExplanationDozSerializers,ExplanationDetailDozSerializers


class ExplanationDozViewSet(viewsets.ModelViewSet):
    queryset = ExplanationDoz.objects.all().order_by('id')

    def get_serializer_class(self):
        # List için hafif serializer, detay için tam serializer
        if self.action == 'get_dosage_by_explanation':
            return ExplanationDetailDozSerializers
        return ExplanationDozSerializers

    @action(detail=False, methods=['get'], url_path='get-dosage-by-explanation')
    def get_dosage_by_explanation(self, request):
        # İlac ID bilgisini alıyoruz
        ilac_id = request.query_params.get('ilac_id')

        # İlac ID'nin olup olmadığını kontrol et
        if not ilac_id:
            return Response({"detail": "İlac ID değeri sağlanmadı."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            explanationdoz = ExplanationDoz.objects.get(ilac_id=ilac_id)
            serializer = self.get_serializer(explanationdoz)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except ExplanationDoz.DoesNotExist:
            return Response({"detail": "Uygun dozaj bulunamadı."}, status=status.HTTP_404_NOT_FOUND)


    @action(detail=False, methods=['post'])
    def bulk_create_from_excel(self, request):
        file = request.FILES.get('file')
        if not file:
            return Response({'error': 'No file uploaded'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Read the Excel file
            df = pd.read_excel(file)

            # Check if required columns are present
            required_columns = ['İLAÇ AD', 'Bilgi', 'durum']
            if not all(column in df.columns for column in required_columns):
                return Response({
                    'error': 'Excel file must contain all required columns'
                }, status=status.HTTP_400_BAD_REQUEST)

            # List to store new drug objects
            new_ilac_list = []
            for _, row in df.iterrows():
                # Skip if 'durum' is True (already processed)
                if row['durum'] == True:
                    continue

                try:
                    # Find the related Ilac object
                    ilac = Ilac.objects.get(name=row['İLAÇ AD'])

                    # Check if fields are empty and handle them appropriately

                    bilgi = row['Bilgi'] if pd.notna(row['Bilgi']) else None

                    # Create a new KiloDoz object
                    new_explanation = ExplanationDoz(
                        ilac=ilac,
                        bilgi=bilgi
                    )

                    # Save the new object
                    new_explanation.save()

                except Ilac.DoesNotExist:
                    return Response({'error': f'Ilac with ID {row["İLAÇ AD"]} not found.'},
                                    status=status.HTTP_400_BAD_REQUEST)

            return Response({'status': 'Ilac records created successfully'}, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({'error': f'An error occurred while processing the file: {str(e)}'},
                            status=status.HTTP_400_BAD_REQUEST)



from .models import HatalikYasDoz
from .serializers import HatalikYasDozSerializers,HatalikYasDozDetailSerializers


class HatalikYasDozViewSet(viewsets.ModelViewSet):
    queryset = HatalikYasDoz.objects.all().order_by('id')
    serializer_class = HatalikYasDozSerializers

    def get_serializer_class(self):
        # List için hafif serializer, detay için tam serializer
        if self.action == 'get_dosage_by_age_and_disease':
            return HatalikYasDozDetailSerializers
        return HatalikYasDozSerializers

    @action(detail=False, methods=['get'], url_path='get-dosage-by-age-and-disease')
    def get_dosage_by_age_and_disease(self, request):
        ilac_id = request.query_params.get('ilac_id')
        hastalik_id = request.query_params.get('hastalik_id')

        try:
            yas = int(request.query_params.get('yas', 0))
        except ValueError:
            return Response({'error': 'Yaş geçersiz.'}, status=status.HTTP_400_BAD_REQUEST)

        yas_birimi = request.query_params.get('yas_birimi', 'yil')

        if not ilac_id or not hastalik_id:
            return Response({'error': 'İlac ID ve hastalık ID parametreleri gereklidir.'},
                            status=status.HTTP_400_BAD_REQUEST)

        # Yaşı aya çevirme (Eğer yıl verilmişse)
        if yas_birimi == 'yil':
            yas *= 12  # Yılı aya çeviriyoruz

        # İlac ID ve hastalık ID'ye göre filtreleme
        yas_doz_list = HatalikYasDoz.objects.filter(ilac_id=ilac_id, hastaliklar_id=hastalik_id, min_yas__lte=yas,
                                                    maks_yas__gte=yas)


        if yas_doz_list.exists():
            yas_doz = yas_doz_list.first()
            serializer = self.get_serializer(yas_doz)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response({"detail": "Belirtilen ilac ID ve hastalık ID'ye uygun dozaj bulunamadı."},
                            status=status.HTTP_404_NOT_FOUND)

    @action(detail=False, methods=['post'])
    def bulk_create_from_excel(self, request):
        file = request.FILES.get('file')
        if not file:
            return Response({'error': 'No file uploaded'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Read the uploaded Excel file
            df = pd.read_excel(file)

            # Correct column names pattern based on your provided Excel structure
            age_columns = [i for i in range(13)] + [i * 12 for i in
                                                    range(2, 20)]  # ['0', '1', ..., '12', '24', ..., '228']
            required_columns = ['Hastalık Ad', 'İLAÇ AD'] + age_columns + ['Yüksek Yaş Sınırı',
                                                                           'Yüksek Yaş Sınırı Sonrası Uyarı', 'durum']

            if not all(column in df.columns for column in required_columns):
                return Response({'error': 'Excel file is missing required columns.'},
                                status=status.HTTP_400_BAD_REQUEST)

            yas_doz_objects = []

            # Iterate through each row in the DataFrame
            for index, row in df.iterrows():
                # Only process rows where 'durum' is False
                if not row['durum']:
                    try:
                        # Fetch the Ilac object using 'İLAÇ AD'
                        ilac = Ilac.objects.get(name=row['İLAÇ AD'])

                        # Fetch the Hastalik object using 'Hastalık Ad'
                        hastalik = Hastalik.objects.get(name=row['Hastalık Ad'])

                        # Track the current dosage value and age range
                        current_doz = None
                        min_yas = 0

                        # Iterate through the age columns in the corrected order
                        for age_str in age_columns:
                            doz = row[age_str]

                            # If the dosage changes or we reach the last age column
                            if doz != current_doz or age_str == age_columns[-1]:
                                if current_doz is not None:
                                    # Create a YasDoz object for the previous age range
                                    maks_yas = int(age_str) - 1 if age_str != age_columns[-1] else int(age_str)
                                    yas_doz_objects.append(
                                        HatalikYasDoz(
                                            ilac=ilac,
                                            doz=current_doz,
                                            min_yas=min_yas,
                                            maks_yas=maks_yas,
                                            hastaliklar=hastalik
                                        )
                                    )
                                # Update current dosage and reset min_yas
                                current_doz = doz
                                min_yas = int(age_str)

                        # Handle the final dosage range (from 228 to Yüksek Yaş using 228's dose)
                        if 'Yüksek Yaş Sınırı' in row and 'Yüksek Yaş Sınırı Sonrası Uyarı' in row:
                            yas_doz_objects.append(
                                HatalikYasDoz(
                                    ilac=ilac,
                                    doz=row[228],  # Use the dosage value from age 228
                                    min_yas=228,
                                    maks_yas=row['Yüksek Yaş Sınırı'],  # Set the 'maks_yas' to 'Yüksek Yaş'
                                    hastaliklar=hastalik
                                )
                            )

                            # Handle the dosage for ages greater than "Yüksek Yaş"
                            if pd.notna(row['Yüksek Yaş Sınırı Sonrası Uyarı']):
                                yas_doz_objects.append(
                                    HatalikYasDoz(
                                        ilac=ilac,
                                        hastaliklar=hastalik,
                                        doz=row['Yüksek Yaş Sınırı Sonrası Uyarı'],
                                        # Use the 'Yas uyarı' value for dosage
                                        min_yas=row['Yüksek Yaş Sınırı'] + 1,
                                        # Set min_yas to one more than 'Yüksek Yaş'
                                        maks_yas=9999  # Use a large integer value to represent ages beyond "Yüksek Yaş"
                                    )
                                )

                    except Ilac.DoesNotExist:
                        return Response({'error': f'Ilac with name {row["İLAÇ AD"]} not found.'},
                                        status=status.HTTP_400_BAD_REQUEST)
                    except Hastalik.DoesNotExist:
                        return Response({'error': f'Hastalik with name {row["Hastalık Ad"]} not found.'},
                                        status=status.HTTP_400_BAD_REQUEST)

            # Perform bulk creation of YasDoz objects
            if yas_doz_objects:
                with transaction.atomic():
                    HatalikYasDoz.objects.bulk_create(yas_doz_objects)
                return Response({"message": f"{len(yas_doz_objects)} records created successfully."},
                                status=status.HTTP_201_CREATED)
            else:
                return Response({"message": "No records to create."}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




from .models import HastalikKiloDoz
from .serializers import HastalikKiloDozSerializers


class HastalikKiloDozViewSet(viewsets.ModelViewSet,BaseOlcekHesaplayici):
    queryset = HastalikKiloDoz.objects.all().order_by('id')
    serializer_class = HastalikKiloDozSerializers


    @action(detail=False, methods=['get'], url_path='get-dosage-by-weight-and-condition')
    def get_dosage_by_weight_and_condition(self, request):
        kilo = request.query_params.get('kilo')
        ilac_id = request.query_params.get('ilac_id')
        hastalik_id = request.query_params.get('hastalik_id')

        if not kilo:
            return Response({'error': 'Kilo değeri sağlanmadı'}, status=status.HTTP_400_BAD_REQUEST)

        if not ilac_id:
            return Response({'error': 'İlaç ID değeri sağlanmadı'}, status=status.HTTP_400_BAD_REQUEST)

        kilodoz = HastalikKiloDoz.objects.filter(ilac_id=ilac_id, hastaliklar_id=hastalik_id).first()

        if not kilodoz:
            return Response({'error': 'doz bilgisi bulunamadı'}, status=status.HTTP_404_NOT_FOUND)

        tipik_min_doz = kilodoz.tipik_min_doz or Decimal('0')
        tipik_max_doz = kilodoz.tipik_max_doz  # Maks doz boş olabilir
        maksimum_anlik_doz = kilodoz.maksimum_anlik_doz or Decimal('0')

        try:
            kilo = Decimal(str(kilo))
        except ValueError:
            return Response({'error': 'Kilo değeri geçersiz'}, status=status.HTTP_400_BAD_REQUEST)

        # Minimum doz hesaplama
        min_doz = kilo * tipik_min_doz

        if tipik_max_doz is None:
            # `tipik_max_doz` değeri yoksa sadece minimum doz üzerinden hesapla
            if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                min_kasik = (min_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                min_kasik_mesaj = self.olcek_formatla(min_kasik)
                doz_message = f"{min_kasik_mesaj} kullanın."
            else:
                doz_message = f"{min_doz} ml kullanın."


        else:
            # `tipik_max_doz` mevcutsa maksimum doz hesaplama
            maks_doz = kilo * tipik_max_doz

            # Eğer minimum doz veya maksimum doz, maksimum anlık dozu geçiyorsa
            if min_doz > maksimum_anlik_doz or maks_doz > maksimum_anlik_doz:
                # Maksimum anlık doza göre hesapla
                if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                    maks_kasik = (maksimum_anlik_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'),
                                                                                      rounding=ROUND_HALF_UP)
                    maks_kasik_mesaj = self.olcek_formatla(maks_kasik)
                    doz_message = f"{maks_kasik_mesaj} kullanın."
                else:
                    doz_message = f"{maksimum_anlik_doz} ml kullanın."
            else:
                if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                    # Kaşık ölçüsüne göre min doz hesaplama
                    min_kasik = (min_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                    min_kasik_mesaj = self.olcek_formatla(min_kasik)

                    # Maksimum doz hesaplama
                    maks_kasik = (maks_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                    maks_kasik_mesaj = self.olcek_formatla(maks_kasik)

                    # Eğer minimum ve maksimum ölçü aynıysa, tek mesaj göster
                    if min_kasik_mesaj == maks_kasik_mesaj:
                        doz_message = f"{min_kasik_mesaj} kullanın."
                    else:
                        doz_message = f"{min_kasik_mesaj} veya {maks_kasik_mesaj} kullanın."
                else:
                    doz_message = f"{min_doz} ml  veya {maks_doz} ml kullanın."

        # Kullanıcıya sunulacak ek bilgiler
        response_data = {
            'message': doz_message,
            'kullanim_sikligi': kilodoz.kullanim_sikligi,
            'check_uyari': kilodoz.check_uyari,
            'maksimum_anlik_doz': kilodoz.maksimum_anlik_doz,
        }

        return Response(response_data, status=status.HTTP_200_OK)




    @action(detail=False, methods=['post'])
    def bulk_create_from_excel(self, request):
        file = request.FILES.get('file')
        if not file:
            return Response({'error': 'No file uploaded'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Excel dosyasını oku
            df = pd.read_excel(file)

            # Gerekli sütunların mevcut olup olmadığını kontrol et
            required_columns = ['Hastalık Ad','İLAÇ AD', 'durum', 'Kullanım sıklığı', 'Check Uyarı',
                                'TİPİK MİN DOZ', 'TİPİK MAX DOZ', 'Maksimum anlık']
            if not all(column in df.columns for column in required_columns):
                return Response({
                    'error': 'Excel file must contain all required columns'
                }, status=status.HTTP_400_BAD_REQUEST)

            for _, row in df.iterrows():
                # Eğer 'durum' True ise (zaten işlenmiş), atla
                if row['durum'] == True:
                    continue

                try:
                    # İlgili Ilac nesnesini bul
                    ilac = Ilac.objects.get(name=row['İLAÇ AD'])

                    hastalik = Hastalik.objects.get(name=row['Hastalık Ad'])

                    # Konsantrasyon oranını hesapla
                    kontsantrasyon_orani = ilac.kontsantrasyon_mg / ilac.kontsantrasyon_ml

                    # Alanları kontrol et ve uygun şekilde işle
                    # Tipik min doz hesabı
                    tipik_min_doz = row['TİPİK MİN DOZ'] if pd.notna(row['TİPİK MİN DOZ']) else None
                    if tipik_min_doz is not None:
                        tipik_min_doz = Decimal(tipik_min_doz) / kontsantrasyon_orani

                    # Tipik max doz hesabı
                    tipik_max_doz = row['TİPİK MAX DOZ'] if pd.notna(row['TİPİK MAX DOZ']) else None
                    if tipik_max_doz is not None:
                        tipik_max_doz = Decimal(tipik_max_doz) / kontsantrasyon_orani

                    # Maksimum anlık doz hesabı
                    maksimum_anlik_doz = row['Maksimum anlık'] if pd.notna(row['Maksimum anlık']) else None
                    if maksimum_anlik_doz is not None:
                        maksimum_anlik_doz = Decimal(maksimum_anlik_doz) / kontsantrasyon_orani



                    check_uyari = row.get('Check Uyarı', '')
                    if pd.isna(check_uyari):
                        check_uyari = ''

                    # Yeni KiloDoz nesnesi oluştur
                    new_ilac = HastalikKiloDoz(
                        kullanim_sikligi=row['Kullanım sıklığı'],
                        ilac=ilac,
                        check_uyari=check_uyari,
                        tipik_min_doz=tipik_min_doz,
                        tipik_max_doz=tipik_max_doz,
                        maksimum_anlik_doz=maksimum_anlik_doz,
                        hastaliklar=hastalik,
                    )

                    # Yeni nesneyi kaydet
                    new_ilac.save()

                except Ilac.DoesNotExist:
                    return Response({'error': f'Ilac with ID {row["ILAC ID"]} not found.'},
                                    status=status.HTTP_400_BAD_REQUEST)

                except Hastalik.DoesNotExist:
                    return Response({'error': f'Hastalik with name {row["Hastalık Ad"]} not found.'},
                                    status=status.HTTP_400_BAD_REQUEST)

            return Response({'status': 'Ilac records created successfully'}, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({'error': f'An error occurred while processing the file: {str(e)}'},
                            status=status.HTTP_400_BAD_REQUEST)




from .models import ArtanKiloDoz
from .serializers import ArtanKiloDozSerializers


class ArtanKiloDozViewSet(viewsets.ModelViewSet,BaseOlcekHesaplayici):
    queryset = ArtanKiloDoz.objects.all().order_by('id')
    serializer_class = ArtanKiloDozSerializers


    @action(detail=False, methods=['get'], url_path='get-artan-doz-kilo')
    def get_artan_doz_kilo(self, request):
        kilo = request.query_params.get('kilo')
        ilac_id = request.query_params.get('ilac_id')

        if not kilo:
            return Response({'error': 'Kilo değeri sağlanmadı'}, status=status.HTTP_400_BAD_REQUEST)

        if not ilac_id:
            return Response({'error': 'İlaç ID değeri sağlanamadı'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            kilodoz = ArtanKiloDoz.objects.get(ilac_id=ilac_id)
        except ArtanKiloDoz.DoesNotExist:
            return Response({'error': 'doz bilgisi bulunamadı'}, status=status.HTTP_404_NOT_FOUND)

        try:
            kilo = Decimal(str(kilo))
        except ValueError:
            return Response({'error': 'Kilo değeri geçersiz'}, status=status.HTTP_400_BAD_REQUEST)

        if kilodoz.threshold_weight < kilo:
            tipik_min_doz = kilodoz.tipik_min_doz
            tipik_max_doz = kilodoz.tipik_max_doz
            maksimum_anlik_doz = kilodoz.maksimum_anlik_doz or Decimal('0')

            min_doz = kilo * tipik_min_doz

            if tipik_max_doz is None:
                # `tipik_max_doz` değeri yoksa sadece minimum doz üzerinden hesapla
                if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                    min_kasik = (min_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                    min_kasik_mesaj = self.olcek_formatla(min_kasik)
                    doz_message = f"{min_kasik_mesaj} kullanın."
                else:
                    doz_message = f"{min_doz} ml kullanın."
            else:
                # `tipik_max_doz` mevcutsa maksimum doz hesaplama
                maks_doz = kilo * tipik_max_doz

                # Eğer minimum doz veya maksimum doz, maksimum anlık dozu geçiyorsa
                if min_doz > maksimum_anlik_doz or maks_doz > maksimum_anlik_doz:
                    # Maksimum anlık doza göre hesapla
                    if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                        maks_kasik = (maksimum_anlik_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'),
                                                                                          rounding=ROUND_HALF_UP)
                        maks_kasik_mesaj = self.olcek_formatla(maks_kasik)
                        doz_message = f"{maks_kasik_mesaj} kullanın."
                    else:
                        doz_message = f"{maksimum_anlik_doz} ml kullanın."
                else:
                    if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                        # Kaşık ölçüsüne göre min doz hesaplama
                        min_kasik = (min_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                        min_kasik_mesaj = self.olcek_formatla(min_kasik)

                        # Maksimum doz hesaplama
                        maks_kasik = (maks_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                        maks_kasik_mesaj = self.olcek_formatla(maks_kasik)

                        # Eğer minimum ve maksimum ölçü aynıysa, tek mesaj göster
                        if min_kasik_mesaj == maks_kasik_mesaj:
                            doz_message = f"{min_kasik_mesaj} kullanın."
                        else:
                            doz_message = f"{min_kasik_mesaj} veya {maks_kasik_mesaj} kullanın."
                    else:
                        doz_message = f"{min_doz} ml  veya {maks_doz} ml kullanın."

            response_data = {
                'message': doz_message,
                'kullanim_sikligi': kilodoz.kullanim_sikligi,
                'check_uyari': kilodoz.check_uyari,
                'maksimum_anlik_doz': kilodoz.maksimum_anlik_doz,
            }
        else:
            min_doz = kilodoz.threshold_weight_min_dose
            maks_doz = kilodoz.threshold_weight_max_dose

            if min_doz is None and maks_doz is None:
                doz_message = "Kullanımı önerilmez."
            else:
                if maks_doz is None:
                    if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                        min_kasik = (min_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                        min_kasik_mesaj = self.olcek_formatla(min_kasik)
                        doz_message = f"{min_kasik_mesaj} kullanın."
                    else:
                        doz_message = f"{min_doz} ml kullanın."
                else:
                    if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                        min_kasik = (min_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                        min_kasik_mesaj = self.olcek_formatla(min_kasik)
                        maks_kasik = (maks_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                        maks_kasik_mesaj = self.olcek_formatla(maks_kasik)

                        if min_kasik_mesaj == maks_kasik_mesaj:
                            doz_message = f"{min_kasik_mesaj} kullanın."
                        else:
                            doz_message = f"{min_kasik_mesaj} veya {maks_kasik_mesaj} kullanın."
                    else:
                        doz_message = f"{min_doz} ml  veya {maks_doz} ml kullanın."

            response_data = {
                'message': doz_message,
                'kullanim_sikligi': kilodoz.kullanim_sikligi,
                'check_uyari': kilodoz.check_uyari,
                'maksimum_anlik_doz': kilodoz.maksimum_anlik_doz,
            }

        return Response(response_data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['post'])
    def bulk_create_from_excel(self, request):
        file = request.FILES.get('file')
        if not file:
            return Response({'error': 'No file uploaded'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Excel dosyasını oku
            df = pd.read_excel(file)

            # Gerekli sütunların mevcut olup olmadığını kontrol et
            required_columns = ['İLAÇ AD', 'durum','Kilo', 'ALTI','Kullanım sıklığı', 'Check Uyarı',
                                'TİPİK MİN DOZ', 'TİPİK MAX DOZ', 'Maksimum anlık']
            if not all(column in df.columns for column in required_columns):
                return Response({
                    'error': 'Excel file must contain all required columns'
                }, status=status.HTTP_400_BAD_REQUEST)

            for _, row in df.iterrows():
                # Eğer 'durum' True ise (zaten işlenmiş), atla
                if row['durum'] == True:
                    continue

                try:
                    # İlgili Ilac nesnesini bul
                    ilac = Ilac.objects.get(name=row['İLAÇ AD'])

                    # Konsantrasyon oranını hesapla
                    kontsantrasyon_orani = ilac.kontsantrasyon_mg / ilac.kontsantrasyon_ml

                    # Alanları kontrol et ve uygun şekilde işle
                    # Tipik min doz hesabı
                    tipik_min_doz = row['TİPİK MİN DOZ'] if pd.notna(row['TİPİK MİN DOZ']) else None
                    if tipik_min_doz is not None:
                        tipik_min_doz = Decimal(tipik_min_doz) / kontsantrasyon_orani

                    # Tipik max doz hesabı
                    tipik_max_doz = row['TİPİK MAX DOZ'] if pd.notna(row['TİPİK MAX DOZ']) else None
                    if tipik_max_doz is not None:
                        tipik_max_doz = Decimal(tipik_max_doz) / kontsantrasyon_orani

                    # Maksimum anlık doz hesabı
                    maksimum_anlik_doz = row['Maksimum anlık'] if pd.notna(row['Maksimum anlık']) else None
                    if maksimum_anlik_doz is not None:
                        maksimum_anlik_doz = Decimal(maksimum_anlik_doz) / kontsantrasyon_orani



                    threshold_weight_min_dose = Decimal('0')
                    threshold_weight_max_dose = Decimal('0')

                    if pd.notna(row['ALTI']) and row['ALTI'].strip():
                        # Parse 'ALTI' list and convert values to Decimal
                        alti_list = row['ALTI'].strip('[]').split()
                        alti_list = [Decimal(x) for x in alti_list]

                        # Check if the list has at least 1 element
                        if len(alti_list) >= 1:
                            # Multiply the first element by 'kontsantrasyon_orani' and assign to min dose
                            threshold_weight_min_dose = alti_list[0] / kontsantrasyon_orani


                        # Check if the list has a second element and assign to max dose
                        if len(alti_list) >= 2:
                            threshold_weight_max_dose = alti_list[1] / kontsantrasyon_orani
                            print("threshold_weight_max_dose:",threshold_weight_max_dose)





                    check_uyari = row.get('Check Uyarı', '')
                    if pd.isna(check_uyari):
                        check_uyari = ''

                    # Yeni KiloDoz nesnesi oluştur
                    artankilodoz_data = {
                        'kullanim_sikligi': row['Kullanım sıklığı'],
                        'ilac': ilac,
                        'check_uyari': check_uyari,
                        'tipik_min_doz': tipik_min_doz,
                        'tipik_max_doz': tipik_max_doz,
                        'maksimum_anlik_doz': maksimum_anlik_doz,
                        'threshold_weight': row['Kilo']
                    }

                    # Conditionally add min and max doses if they exist
                    if threshold_weight_min_dose != Decimal('0'):
                        artankilodoz_data['threshold_weight_min_dose'] = threshold_weight_min_dose
                    if threshold_weight_max_dose != Decimal('0'):
                        artankilodoz_data['threshold_weight_max_dose'] = threshold_weight_max_dose

                    # Create the ArtanKiloDoz instance
                    new_ilac = ArtanKiloDoz(**artankilodoz_data)

                    # Yeni nesneyi kaydet
                    new_ilac.save()

                except Ilac.DoesNotExist:
                    return Response({'error': f'Ilac with ID {row["ILAC ID"]} not found.'},
                                    status=status.HTTP_400_BAD_REQUEST)

            return Response({'status': 'Ilac records created successfully'}, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({'error': f'An error occurred while processing the file: {str(e)}'},
                            status=status.HTTP_400_BAD_REQUEST)


from .models import AzalanKiloDoz
from .serializers import AzalanKiloDozSerializers


class AzalanKiloDozViewSet(viewsets.ModelViewSet,BaseOlcekHesaplayici):
    queryset = AzalanKiloDoz.objects.all().order_by('id')
    serializer_class = AzalanKiloDozSerializers


    @action(detail=False, methods=['get'], url_path='get-azalan-doz-kilo')
    def get_azalan_doz_kilo(self, request):
        kilo = request.query_params.get('kilo')
        ilac_id = request.query_params.get('ilac_id')

        if not kilo:
            return Response({'error': 'Kilo değeri sağlanmadı'}, status=status.HTTP_400_BAD_REQUEST)

        if not ilac_id:
            return Response({'error': 'İlaç ID değeri sağlanamadı'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            kilodoz = AzalanKiloDoz.objects.get(ilac_id=ilac_id)
        except AzalanKiloDoz.DoesNotExist:
            return Response({'error': 'doz bilgisi bulunamadı'}, status=status.HTTP_404_NOT_FOUND)

        try:
            kilo = Decimal(str(kilo))
        except ValueError:
            return Response({'error': 'Kilo değeri geçersiz'}, status=status.HTTP_400_BAD_REQUEST)

        if kilodoz.threshold_weight > kilo:
            tipik_min_doz = kilodoz.tipik_min_doz or Decimal('0')
            tipik_max_doz = kilodoz.tipik_max_doz

            min_doz = kilo * tipik_min_doz

            if tipik_max_doz is None:
                # Only minimum dose calculation
                if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                    min_kasik = (min_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                    min_kasik_mesaj = self.olcek_formatla(min_kasik)
                    doz_message = f"{min_kasik_mesaj} kullanın."
                else:
                    doz_message = f"{min_doz} ml kullanın."
            else:
                maks_doz = kilo * tipik_max_doz
                if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                    min_kasik = (min_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                    min_kasik_mesaj = self.olcek_formatla(min_kasik)
                    maks_kasik = (maks_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                    maks_kasik_mesaj = self.olcek_formatla(maks_kasik)

                    if min_kasik_mesaj == maks_kasik_mesaj:
                        doz_message = f"{min_kasik_mesaj} kullanın."
                    else:
                        doz_message = f"{min_kasik_mesaj} veya {maks_kasik_mesaj} kullanın."
                else:
                    doz_message = f"{min_doz} ml veya {maks_doz} ml kullanın."

            response_data = {
                'message': doz_message,
                'kullanim_sikligi': kilodoz.kullanim_sikligi,
                'check_uyari': kilodoz.check_uyari,
            }
        else:
            min_doz = kilodoz.threshold_weight_min_dose
            maks_doz = kilodoz.threshold_weight_max_dose

            if min_doz is None and maks_doz is None:
                doz_message = "Kullanımı önerilmez."
            else:
                if maks_doz is None:
                    if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                        min_kasik = (min_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                        min_kasik_mesaj = self.olcek_formatla(min_kasik)
                        doz_message = f"{min_kasik_mesaj} kullanın."
                    else:
                        doz_message = f"{min_doz} ml kullanın."
                else:
                    if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                        min_kasik = (min_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                        min_kasik_mesaj = self.olcek_formatla(min_kasik)
                        maks_kasik = (maks_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                        maks_kasik_mesaj = self.olcek_formatla(maks_kasik)

                        if min_kasik_mesaj == maks_kasik_mesaj:
                            doz_message = f"{min_kasik_mesaj} kullanın."
                        else:
                            doz_message = f"{min_kasik_mesaj} veya {maks_kasik_mesaj} kullanın."
                    else:
                        doz_message = f"{min_doz} ml veya {maks_doz} ml kullanın."

            response_data = {
                'message': doz_message,
                'kullanim_sikligi': kilodoz.kullanim_sikligi,
                'check_uyari': kilodoz.check_uyari,
            }

        return Response(response_data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['post'])
    def bulk_create_from_excel(self, request):
        file = request.FILES.get('file')
        if not file:
            return Response({'error': 'No file uploaded'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Excel dosyasını oku
            df = pd.read_excel(file)

            # Gerekli sütunların mevcut olup olmadığını kontrol et
            required_columns = ['İLAÇ AD', 'durum', 'Kilo', 'ÜSTÜ', 'Kullanım sıklığı','Check Uyarı', 'TİPİK MİN DOZ', 'TİPİK MAX DOZ']

            if not all(column in df.columns for column in required_columns):
                return Response({
                    'error': 'Excel file must contain all required columns'
                }, status=status.HTTP_400_BAD_REQUEST)

            for _, row in df.iterrows():
                # Eğer 'durum' True ise (zaten işlenmiş), atla
                if row['durum'] == True or not pd.notna(row['İLAÇ AD'])  :
                    continue

                try:
                    # İlgili Ilac nesnesini bul
                    ilac = Ilac.objects.get(name=row['İLAÇ AD'])

                    # Konsantrasyon oranını hesapla
                    kontsantrasyon_orani = ilac.kontsantrasyon_mg / ilac.kontsantrasyon_ml

                    # Alanları kontrol et ve uygun şekilde işle
                    # Tipik min doz hesabı
                    tipik_min_doz = row['TİPİK MİN DOZ'] if pd.notna(row['TİPİK MİN DOZ']) else None
                    if tipik_min_doz is not None:
                        tipik_min_doz = Decimal(tipik_min_doz) / kontsantrasyon_orani

                    # Tipik max doz hesabı
                    tipik_max_doz = row['TİPİK MAX DOZ'] if pd.notna(row['TİPİK MAX DOZ']) else None
                    if tipik_max_doz is not None:
                        tipik_max_doz = Decimal(tipik_max_doz) / kontsantrasyon_orani



                    threshold_weight_min_dose = Decimal('0')
                    threshold_weight_max_dose = Decimal('0')

                    if pd.notna(row['ÜSTÜ']) and row['ÜSTÜ'].strip():
                        # Parse 'ÜSTÜ' list and convert values to Decimal
                        alti_list = row['ÜSTÜ'].strip('[]').split()
                        alti_list = [Decimal(x) for x in alti_list]

                        # Check if the list has at least 1 element
                        if len(alti_list) >= 1:
                            # Multiply the first element by 'kontsantrasyon_orani' and assign to min dose
                            threshold_weight_min_dose = alti_list[0] / kontsantrasyon_orani
                            print("threshold_weight_min_dose:",threshold_weight_min_dose)

                        # Check if the list has a second element and assign to max dose
                        if len(alti_list) >= 2:
                            threshold_weight_max_dose = alti_list[1] / kontsantrasyon_orani
                            print("threshold_weight_max_dose:", threshold_weight_max_dose)


                    check_uyari = row.get('Check Uyarı', '')
                    if pd.isna(check_uyari):
                        check_uyari = ''

                    # Yeni KiloDoz nesnesi oluştur
                    artankilodoz_data = {
                        'kullanim_sikligi': row['Kullanım sıklığı'],
                        'ilac': ilac,
                        'check_uyari': check_uyari,
                        'tipik_min_doz': tipik_min_doz,
                        'tipik_max_doz': tipik_max_doz,
                        'threshold_weight': row['Kilo']
                    }

                    # Conditionally add min and max doses if they exist
                    if threshold_weight_min_dose != Decimal('0'):
                        artankilodoz_data['threshold_weight_min_dose'] = threshold_weight_min_dose
                    if threshold_weight_max_dose != Decimal('0'):
                        artankilodoz_data['threshold_weight_max_dose'] = threshold_weight_max_dose

                    # Create the ArtanKiloDoz instance
                    new_ilac = AzalanKiloDoz(**artankilodoz_data)

                    # Yeni nesneyi kaydet
                    new_ilac.save()

                except Ilac.DoesNotExist:
                    return Response({'error': f'Ilac with name {row["İLAÇ AD"]} not found.'}, status=status.HTTP_400_BAD_REQUEST)



            return Response({'status': 'Ilac records created successfully'}, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({'error': f'An error occurred while processing the file: {str(e)}'},
                            status=status.HTTP_400_BAD_REQUEST)





from .models import HastalikArtanKiloDoz
from .serializers import HastalikArtanKiloDozSerializers


class HastalikArtanKiloDozViewSet(viewsets.ModelViewSet,BaseOlcekHesaplayici):
    queryset = HastalikArtanKiloDoz.objects.all().order_by('id')
    serializer_class = HastalikArtanKiloDozSerializers

    @action(detail=False, methods=['get'], url_path='get-hastalik-artan-doz-kilo')
    def get_hastalik_artan_doz_kilo(self, request):
        kilo = request.query_params.get('kilo')
        ilac_id = request.query_params.get('ilac_id')
        hastalik_id = request.query_params.get('hastalik_id')

        if not kilo:
            return Response({'error': 'Kilo değeri sağlanmadı'}, status=status.HTTP_400_BAD_REQUEST)

        if not ilac_id:
            return Response({'error': 'İlaç ID değeri sağlanamadı'}, status=status.HTTP_400_BAD_REQUEST)

        if not hastalik_id:
            return Response({'error': 'Hastalık ID değeri sağlanamadı'}, status=status.HTTP_400_BAD_REQUEST)


        kilodoz = HastalikArtanKiloDoz.objects.filter(ilac_id=ilac_id,hastaliklar_id=hastalik_id).first()

        if not kilodoz:
            return Response({'error': 'doz bilgisi bulunamadı'}, status=status.HTTP_404_NOT_FOUND)

        try:
            kilo = Decimal(str(kilo))
        except ValueError:
            return Response({'error': 'Kilo değeri geçersiz'}, status=status.HTTP_400_BAD_REQUEST)

        if kilodoz.threshold_weight < kilo:
            tipik_min_doz = kilodoz.tipik_min_doz or Decimal('0')
            tipik_max_doz = kilodoz.tipik_max_doz
            maksimum_anlik_doz = kilodoz.maksimum_anlik_doz or Decimal('0')

            min_doz = kilo * tipik_min_doz

            if tipik_max_doz is None:
                # Only minimum dose calculation
                if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                    min_kasik = (min_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                    min_kasik_mesaj = self.olcek_formatla(min_kasik)
                    doz_message = f"{min_kasik_mesaj} kullanın."
                else:
                    doz_message = f"{min_doz} ml kullanın."
            else:
                maks_doz = kilo * tipik_max_doz

                if min_doz > maksimum_anlik_doz or maks_doz > maksimum_anlik_doz:
                    if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                        maks_kasik = (maksimum_anlik_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                        maks_kasik_mesaj = self.olcek_formatla(maks_kasik)
                        doz_message = f"{maks_kasik_mesaj} kullanın."
                    else:
                        doz_message = f"{maksimum_anlik_doz} kullanın."

                else:
                    if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                        min_kasik = (min_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                        min_kasik_mesaj = self.olcek_formatla(min_kasik)
                        maks_kasik = (maks_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                        maks_kasik_mesaj = self.olcek_formatla(maks_kasik)

                        if min_kasik_mesaj == maks_kasik_mesaj:
                            doz_message = f"{min_kasik_mesaj} kullanın."
                        else:
                            doz_message = f"{min_kasik_mesaj} veya {maks_kasik_mesaj} kullanın."
                    else:
                            doz_message = f"{min_doz} ml veya {maks_doz} ml kullanın."



            response_data = {
                'message': doz_message,
                'kullanim_sikligi': kilodoz.kullanim_sikligi,
                'check_uyari': kilodoz.check_uyari,
                'maksimum_anlik_doz': kilodoz.maksimum_anlik_doz,
            }
        else:
            min_doz = kilodoz.threshold_weight_min_dose
            maks_doz = kilodoz.threshold_weight_max_dose


            if min_doz is None and maks_doz is None:
                doz_message = "Kullanımı önerilmez."
            else:
                if maks_doz is None:
                    if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                        min_kasik = (min_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                        min_kasik_mesaj = self.olcek_formatla(min_kasik)
                        doz_message = f"{min_kasik_mesaj} kullanın."
                    else:
                        doz_message = f"{min_doz} ml kullanın."
                else:
                    if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                        min_kasik = (min_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                        min_kasik_mesaj = self.olcek_formatla(min_kasik)
                        maks_kasik = (maks_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                        maks_kasik_mesaj = self.olcek_formatla(maks_kasik)

                        if min_kasik_mesaj == maks_kasik_mesaj:
                            doz_message = f"{min_kasik_mesaj} kullanın."
                        else:
                            doz_message = f"{min_kasik_mesaj} veya {maks_kasik_mesaj} kullanın."
                    else:
                        doz_message = f"{min_doz} ml veya {maks_doz} ml kullanın."

            response_data = {
                'message': doz_message,
                'kullanim_sikligi': kilodoz.kullanim_sikligi,
                'check_uyari': kilodoz.check_uyari,
                'maksimum_anlik_doz': kilodoz.maksimum_anlik_doz,
            }

        return Response(response_data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['post'])
    def bulk_create_from_excel(self, request):
        file = request.FILES.get('file')
        if not file:
            return Response({'error': 'No file uploaded'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Excel dosyasını oku
            df = pd.read_excel(file)

            # Gerekli sütunların mevcut olup olmadığını kontrol et
            required_columns = ['Hastalık Ad','İLAÇ AD', 'durum','Kilo', 'ALTI','Kullanım sıklığı','Check Uyarı',
                                'TİPİK MİN DOZ', 'TİPİK MAX DOZ', 'Maksimum anlık']
            if not all(column in df.columns for column in required_columns):
                return Response({
                    'error': 'Excel file must contain all required columns'
                }, status=status.HTTP_400_BAD_REQUEST)

            for _, row in df.iterrows():
                # Eğer 'durum' True ise (zaten işlenmiş), atla
                if row['durum'] == True:
                    continue

                try:
                    # İlgili Ilac nesnesini bul
                    ilac = Ilac.objects.get(name=row['İLAÇ AD'])


                    hastalik = Hastalik.objects.get(name=row['Hastalık Ad'])

                    print("hastalik:",hastalik)

                    # Konsantrasyon oranını hesapla
                    kontsantrasyon_orani = ilac.kontsantrasyon_mg / ilac.kontsantrasyon_ml

                    # Alanları kontrol et ve uygun şekilde işle
                    # Tipik min doz hesabı
                    tipik_min_doz = row['TİPİK MİN DOZ'] if pd.notna(row['TİPİK MİN DOZ']) else None
                    if tipik_min_doz is not None:
                        tipik_min_doz = Decimal(tipik_min_doz) / kontsantrasyon_orani

                    # Tipik max doz hesabı
                    tipik_max_doz = row['TİPİK MAX DOZ'] if pd.notna(row['TİPİK MAX DOZ']) else None
                    if tipik_max_doz is not None:
                        tipik_max_doz = Decimal(tipik_max_doz) / kontsantrasyon_orani

                    # Maksimum anlık doz hesabı
                    maksimum_anlik_doz = row['Maksimum anlık'] if pd.notna(row['Maksimum anlık']) else None
                    if maksimum_anlik_doz is not None:
                        maksimum_anlik_doz = Decimal(maksimum_anlik_doz) / kontsantrasyon_orani



                    threshold_weight_min_dose = Decimal('0')
                    threshold_weight_max_dose = Decimal('0')

                    if pd.notna(row['ALTI']) and row['ALTI'].strip():
                        # Parse 'ALTI' list and convert values to Decimal
                        alti_list = row['ALTI'].strip('[]').split()
                        alti_list = [Decimal(x) for x in alti_list]

                        # Check if the list has at least 1 element
                        if len(alti_list) >= 1:
                            # Multiply the first element by 'kontsantrasyon_orani' and assign to min dose
                            threshold_weight_min_dose = alti_list[0] / kontsantrasyon_orani


                        # Check if the list has a second element and assign to max dose
                        if len(alti_list) >= 2:
                            threshold_weight_max_dose = alti_list[1] / kontsantrasyon_orani
                            print("threshold_weight_max_dose:",threshold_weight_max_dose)





                    check_uyari = row.get('Check Uyarı', '')
                    if pd.isna(check_uyari):
                        check_uyari = ''

                    # Yeni KiloDoz nesnesi oluştur
                    artankilodoz_data = {
                        'kullanim_sikligi': row['Kullanım sıklığı'],
                        'ilac': ilac,
                        'check_uyari': check_uyari,
                        'tipik_min_doz': tipik_min_doz,
                        'tipik_max_doz': tipik_max_doz,
                        'maksimum_anlik_doz': maksimum_anlik_doz,
                        'threshold_weight': row['Kilo'],
                        'hastaliklar': hastalik
                    }

                    # Conditionally add min and max doses if they exist
                    if threshold_weight_min_dose != Decimal('0'):
                        artankilodoz_data['threshold_weight_min_dose'] = threshold_weight_min_dose
                    if threshold_weight_max_dose != Decimal('0'):
                        artankilodoz_data['threshold_weight_max_dose'] = threshold_weight_max_dose

                    # Create the ArtanKiloDoz instance
                    new_ilac = HastalikArtanKiloDoz(**artankilodoz_data)

                    # Yeni nesneyi kaydet
                    new_ilac.save()

                except Ilac.DoesNotExist:
                    return Response({'error': f"Ilac '{row['İLAÇ AD']}' not found"}, status=status.HTTP_400_BAD_REQUEST)

            return Response({'status': 'Ilac records created successfully'}, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({'error': f'An error occurred while processing the file: {str(e)}'},
                            status=status.HTTP_400_BAD_REQUEST)



from .models import HastalikAzalanKiloDoz
from .serializers import HastalikAzalanKiloDozSerializers

# burdan devam et
class HastalikAzalanKiloDozViewSet(viewsets.ModelViewSet,BaseOlcekHesaplayici):
    queryset = HastalikAzalanKiloDoz.objects.all().order_by('id')
    serializer_class = HastalikAzalanKiloDozSerializers

    @action(detail=False, methods=['get'], url_path='get-hastalik-azalan-doz-kilo')
    def get_hastalik_azalan_doz_kilo(self, request):
        kilo = request.query_params.get('kilo')
        ilac_id = request.query_params.get('ilac_id')
        hastalik_id = request.query_params.get('hastalik_id')

        if not kilo:
            return Response({'error': 'Kilo değeri sağlanmadı'}, status=status.HTTP_400_BAD_REQUEST)

        if not ilac_id:
            return Response({'error': 'İlaç ID değeri sağlanamadı'}, status=status.HTTP_400_BAD_REQUEST)

        if not hastalik_id:
            return Response({'error': 'Hastalık ID değeri sağlanamadı'}, status=status.HTTP_400_BAD_REQUEST)

        kilodoz = HastalikAzalanKiloDoz.objects.filter(ilac_id=ilac_id, hastaliklar_id=hastalik_id).first()

        if not kilodoz:
            return Response({'error': 'doz bilgisi bulunamadı'}, status=status.HTTP_404_NOT_FOUND)

        try:
            kilo = Decimal(str(kilo))
        except ValueError:
            return Response({'error': 'Kilo değeri geçersiz'}, status=status.HTTP_400_BAD_REQUEST)

        if kilodoz.threshold_weight > kilo:
            tipik_min_doz = kilodoz.tipik_min_doz or Decimal('0')
            tipik_max_doz = kilodoz.tipik_max_doz

            min_doz = kilo * tipik_min_doz

            if tipik_max_doz is None:
                # Only minimum dose calculation
                if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                    min_kasik = (min_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                    min_kasik_mesaj = self.olcek_formatla(min_kasik)
                    doz_message = f"{min_kasik_mesaj} kullanın."
                else:
                    doz_message = f"{min_doz} kullanın."
            else:
                maks_doz = kilo * tipik_max_doz
                if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                    min_kasik = (min_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                    min_kasik_mesaj = self.olcek_formatla(min_kasik)
                    maks_kasik = (maks_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                    maks_kasik_mesaj = self.olcek_formatla(maks_kasik)

                    if min_kasik_mesaj == maks_kasik_mesaj:
                        doz_message = f"{min_kasik_mesaj} kullanın."
                    else:
                        doz_message = f"{min_kasik_mesaj} veya {maks_kasik_mesaj} kullanın."
                else:
                    doz_message = f"{min_doz} ml veya {maks_doz} ml kullanın."

            response_data = {
                'message': doz_message,
                'kullanim_sikligi': kilodoz.kullanim_sikligi,
                'check_uyari': kilodoz.check_uyari,
            }
        else:
            min_doz = kilodoz.threshold_weight_min_dose
            maks_doz = kilodoz.threshold_weight_max_dose

            if min_doz is None and maks_doz is None:
                doz_message = "Kullanımı önerilmez."
            else:
                if maks_doz is None:
                    if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                        min_kasik = (min_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                        min_kasik_mesaj = self.olcek_formatla(min_kasik)
                        doz_message = f"{min_kasik_mesaj} kullanın."
                    else:
                        doz_message = f"{min_doz} ml kullanın."
                else:
                    if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                        min_kasik = (min_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                        min_kasik_mesaj = self.olcek_formatla(min_kasik)
                        maks_kasik = (maks_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                        maks_kasik_mesaj = self.olcek_formatla(maks_kasik)

                        if min_kasik_mesaj == maks_kasik_mesaj:
                            doz_message = f"{min_kasik_mesaj} kullanın."
                        else:
                            doz_message = f"{min_kasik_mesaj} veya {maks_kasik_mesaj} kullanın."
                    else:
                        doz_message = f"{min_doz} ml veya {maks_doz} ml kullanın."

            response_data = {
                'message': doz_message,
                'kullanim_sikligi': kilodoz.kullanim_sikligi,
                'check_uyari': kilodoz.check_uyari,
            }

        return Response(response_data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['post'])
    def bulk_create_from_excel(self, request):
        file = request.FILES.get('file')
        if not file:
            return Response({'error': 'No file uploaded'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Excel dosyasını oku
            df = pd.read_excel(file)

            # Gerekli sütunların mevcut olup olmadığını kontrol et
            required_columns = ['Hastalık Ad','İLAÇ AD', 'durum','Kilo', 'ÜSTÜ','Kullanım sıklığı', 'Check Uyarı',
                                'TİPİK MİN DOZ', 'TİPİK MAX DOZ']
            if not all(column in df.columns for column in required_columns):
                return Response({
                    'error': 'Excel file must contain all required columns'
                }, status=status.HTTP_400_BAD_REQUEST)

            for _, row in df.iterrows():
                # Eğer 'durum' True ise (zaten işlenmiş), atla
                if row['durum'] == True:
                    continue

                try:
                    # İlgili Ilac nesnesini bul
                    ilac = Ilac.objects.get(name=row['İLAÇ AD'])

                    hastalik = Hastalik.objects.get(name=row['Hastalık Ad'])

                    # Konsantrasyon oranını hesapla
                    kontsantrasyon_orani = ilac.kontsantrasyon_mg / ilac.kontsantrasyon_ml

                    # Alanları kontrol et ve uygun şekilde işle
                    # Tipik min doz hesabı
                    tipik_min_doz = row['TİPİK MİN DOZ'] if pd.notna(row['TİPİK MİN DOZ']) else None
                    if tipik_min_doz is not None:
                        tipik_min_doz = Decimal(tipik_min_doz) / kontsantrasyon_orani

                    # Tipik max doz hesabı
                    tipik_max_doz = row['TİPİK MAX DOZ'] if pd.notna(row['TİPİK MAX DOZ']) else None
                    if tipik_max_doz is not None:
                        tipik_max_doz = Decimal(tipik_max_doz) / kontsantrasyon_orani


                    threshold_weight_min_dose = Decimal('0')
                    threshold_weight_max_dose = Decimal('0')

                    if pd.notna(row['ÜSTÜ']) and row['ÜSTÜ'].strip():
                        # Parse 'ALTI' list and convert values to Decimal
                        alti_list = row['ÜSTÜ'].strip('[]').split()
                        alti_list = [Decimal(x) for x in alti_list]


                        # Check if the list has at least 1 element
                        if len(alti_list) >= 1:
                            # Multiply the first element by 'kontsantrasyon_orani' and assign to min dose
                            threshold_weight_min_dose = alti_list[0] / kontsantrasyon_orani


                        # Check if the list has a second element and assign to max dose
                        if len(alti_list) >= 2:
                            threshold_weight_max_dose = alti_list[1] / kontsantrasyon_orani


                    check_uyari = row.get('Check Uyarı', '')
                    if pd.isna(check_uyari):
                        check_uyari = ''

                    # Yeni KiloDoz nesnesi oluştur
                    artankilodoz_data = {
                        'kullanim_sikligi': row['Kullanım sıklığı'],
                        'ilac': ilac,
                        'check_uyari': check_uyari,
                        'tipik_min_doz': tipik_min_doz,
                        'tipik_max_doz': tipik_max_doz,
                        'threshold_weight': row['Kilo'],
                        'hastaliklar': hastalik
                    }

                    # Conditionally add min and max doses if they exist
                    if threshold_weight_min_dose != Decimal('0'):
                        artankilodoz_data['threshold_weight_min_dose'] = threshold_weight_min_dose
                    if threshold_weight_max_dose != Decimal('0'):
                        artankilodoz_data['threshold_weight_max_dose'] = threshold_weight_max_dose

                    # Create the ArtanKiloDoz instance
                    new_ilac = HastalikAzalanKiloDoz(**artankilodoz_data)

                    # Yeni nesneyi kaydet
                    new_ilac.save()

                except Ilac.DoesNotExist:
                    return Response({'error': f'Ilac with ID {row["ILAC ID"]} not found.'},
                                    status=status.HTTP_400_BAD_REQUEST)

            return Response({'status': 'Ilac records created successfully'}, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({'error': f'An error occurred while processing the file: {str(e)}'},
                            status=status.HTTP_400_BAD_REQUEST)





from .models import HastalikHemYasaHemKiloyaBagliArtanDoz
from .serializers import HastalikHemYasaHemKiloyaBagliArtanDozSerializers


class HastalikHemYasaHemKiloyaBagliArtanDozViewSet(viewsets.ModelViewSet,BaseOlcekHesaplayici):
    queryset = HastalikHemYasaHemKiloyaBagliArtanDoz.objects.all().order_by('id')
    serializer_class = HastalikHemYasaHemKiloyaBagliArtanDozSerializers


    @action(detail=False, methods=['get'], url_path='get-hastalik-artan-doz-hem-kilo-hem-yas')
    def get_hastalik_artan_doz_hem_kilo_hem_yas(self, request):
        kilo = request.query_params.get('kilo',None)
        age = request.query_params.get('age')
        ilac_id = request.query_params.get('ilac_id')
        hastalik_id = request.query_params.get('hastalik_id')


        if not ilac_id:
            return Response({'error': 'İlaç ID değeri sağlanamadı'}, status=status.HTTP_400_BAD_REQUEST)

        if not hastalik_id:
            return Response({'error': 'Hastalık ID değeri sağlanamadı'}, status=status.HTTP_400_BAD_REQUEST)

        if not age:
            return Response({'error': 'age değeri sağlanamadı'}, status=status.HTTP_400_BAD_REQUEST)


        kilodoz = HastalikHemYasaHemKiloyaBagliArtanDoz.objects.filter(ilac_id=ilac_id, hastaliklar_id=hastalik_id).first()

        if not kilodoz:
            return Response({'error': 'doz bilgisi bulunamadı'}, status=status.HTTP_404_NOT_FOUND)


        if kilodoz.threshold_age < int(age):


            if not kilo:
                return Response({'error': 'Kilo değeri sağlanmadı'}, status=status.HTTP_400_BAD_REQUEST)

            try:
                kilo = Decimal(str(kilo))
            except ValueError:
                return Response({'error': 'Kilo değeri geçersiz'}, status=status.HTTP_400_BAD_REQUEST)


            tipik_min_doz = kilodoz.tipik_min_doz or Decimal('0')
            tipik_max_doz = kilodoz.tipik_max_doz
            maksimum_anlik_doz = kilodoz.maksimum_anlik_doz or Decimal('0')

            min_doz = kilo * tipik_min_doz

            if tipik_max_doz is None:
                # Only minimum dose calculation
                if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                    min_kasik = (min_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                    min_kasik_mesaj = self.olcek_formatla(min_kasik)
                    doz_message = f"{min_kasik_mesaj} kullanın."
                else:
                    doz_message = f"{min_doz} ml kullanın."
            else:
                maks_doz = kilo * tipik_max_doz

                if min_doz > maksimum_anlik_doz or maks_doz > maksimum_anlik_doz:
                    if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                        maks_kasik = (maksimum_anlik_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                        maks_kasik_mesaj = self.olcek_formatla(maks_kasik)
                        doz_message = f"{maks_kasik_mesaj} kullanın."
                    else:
                        doz_message = f"{maksimum_anlik_doz} ml kullanın."
                else:
                    if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                        min_kasik = (min_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                        min_kasik_mesaj = self.olcek_formatla(min_kasik)
                        maks_kasik = (maks_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                        maks_kasik_mesaj = self.olcek_formatla(maks_kasik)

                        if min_kasik_mesaj == maks_kasik_mesaj:
                            doz_message = f"{min_kasik_mesaj} kullanın."
                        else:
                            doz_message = f"{min_kasik_mesaj} veya {maks_kasik_mesaj} kullanın."
                    else:
                        doz_message = f"{min_doz} ml veya {maks_doz} ml kullanın."

            response_data = {
                'message': doz_message,
                'kullanim_sikligi': kilodoz.kullanim_sikligi,
                'check_uyari': kilodoz.check_uyari,
                'maksimum_anlik_doz': kilodoz.maksimum_anlik_doz,
            }
        else:
            min_doz = kilodoz.threshold_age_min_dose
            maks_doz = kilodoz.threshold_age_max_dose

            if min_doz is None and maks_doz is None:
                doz_message = "Kullanımı önerilmez."
            else:
                if maks_doz is None:
                    if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                        min_kasik = (min_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                        min_kasik_mesaj = self.olcek_formatla(min_kasik)
                        doz_message = f"{min_kasik_mesaj} kullanın."
                    else:
                        doz_message = f"{min_doz} ml kullanın."
                else:
                    if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                        min_kasik = (min_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                        min_kasik_mesaj = self.olcek_formatla(min_kasik)
                        maks_kasik = (maks_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                        maks_kasik_mesaj = self.olcek_formatla(maks_kasik)

                        if min_kasik_mesaj == maks_kasik_mesaj:
                            doz_message = f"{min_kasik_mesaj} kullanın."
                        else:
                            doz_message = f"{min_kasik_mesaj} veya {maks_kasik_mesaj} kullanın."
                    else:
                        doz_message = f"{min_doz} ml veya {maks_doz} ml kullanın."

            response_data = {
                'message': doz_message,
                'kullanim_sikligi': kilodoz.kullanim_sikligi,
                'check_uyari': kilodoz.check_uyari,
                'maksimum_anlik_doz': kilodoz.maksimum_anlik_doz,
            }

        return Response(response_data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['post'])
    def bulk_create_from_excel(self, request):
        file = request.FILES.get('file')
        if not file:
            return Response({'error': 'No file uploaded'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Excel dosyasını oku
            df = pd.read_excel(file)

            # Gerekli sütunların mevcut olup olmadığını kontrol et
            required_columns = ['Hastalık Ad','İLAÇ AD', 'durum','Yaş', 'ALTI','Kullanım sıklığı', 'Check Uyarı',
                                'TİPİK MİN DOZ', 'TİPİK MAX DOZ', 'Maksimum anlık']

            if not all(column in df.columns for column in required_columns):

                return Response({
                    'error': 'Excel file must contain all required columns'
                }, status=status.HTTP_400_BAD_REQUEST)

            for _, row in df.iterrows():
                # Eğer 'durum' True ise (zaten işlenmiş), atla
                if row['durum'] == True:
                    continue

                try:
                    # İlgili Ilac nesnesini bul
                    ilac = Ilac.objects.get(name=row['İLAÇ AD'])

                    hastalik = Hastalik.objects.get(name=row['Hastalık Ad'])

                    # Konsantrasyon oranını hesapla
                    kontsantrasyon_orani = ilac.kontsantrasyon_mg / ilac.kontsantrasyon_ml

                    # Alanları kontrol et ve uygun şekilde işle
                    # Tipik min doz hesabı
                    tipik_min_doz = row['TİPİK MİN DOZ'] if pd.notna(row['TİPİK MİN DOZ']) else None
                    if tipik_min_doz is not None:
                        tipik_min_doz = Decimal(tipik_min_doz) / kontsantrasyon_orani

                    # Tipik max doz hesabı
                    tipik_max_doz = row['TİPİK MAX DOZ'] if pd.notna(row['TİPİK MAX DOZ']) else None
                    if tipik_max_doz is not None:
                        tipik_max_doz = Decimal(tipik_max_doz) / kontsantrasyon_orani

                    # Maksimum anlık doz hesabı
                    maksimum_anlik_doz = row['Maksimum anlık'] if pd.notna(row['Maksimum anlık']) else None
                    if maksimum_anlik_doz is not None:
                        maksimum_anlik_doz = Decimal(maksimum_anlik_doz) / kontsantrasyon_orani



                    threshold_age_min_dose = Decimal('0')
                    threshold_age_max_dose = Decimal('0')

                    if pd.notna(row['ALTI']) and row['ALTI'].strip():
                        # Parse 'ALTI' list and convert values to Decimal
                        alti_list = row['ALTI'].strip('[]').split()
                        alti_list = [Decimal(x) for x in alti_list]

                        # Check if the list has at least 1 element
                        if len(alti_list) >= 1:
                            # Multiply the first element by 'kontsantrasyon_orani' and assign to min dose
                            threshold_age_min_dose = alti_list[0] / kontsantrasyon_orani


                        # Check if the list has a second element and assign to max dose
                        if len(alti_list) >= 2:
                            threshold_age_max_dose = alti_list[1] / kontsantrasyon_orani



                    check_uyari = row.get('Check Uyarı', '')
                    if pd.isna(check_uyari):
                        check_uyari = ''

                    # Yeni KiloDoz nesnesi oluştur
                    artankilodoz_data = {
                        'kullanim_sikligi': row['Kullanım sıklığı'],
                        'ilac': ilac,
                        'check_uyari': check_uyari,
                        'tipik_min_doz': tipik_min_doz,
                        'tipik_max_doz': tipik_max_doz,
                        'maksimum_anlik_doz': maksimum_anlik_doz,
                        'threshold_age': row['Yaş'],
                        'hastaliklar': hastalik
                    }

                    # Conditionally add min and max doses if they exist
                    if threshold_age_min_dose != Decimal('0'):
                        artankilodoz_data['threshold_age_min_dose'] = threshold_age_min_dose
                    if threshold_age_max_dose != Decimal('0'):
                        artankilodoz_data['threshold_age_max_dose'] = threshold_age_max_dose

                    # Create the ArtanKiloDoz instance
                    new_ilac = HastalikHemYasaHemKiloyaBagliArtanDoz(**artankilodoz_data)

                    # Yeni nesneyi kaydet
                    new_ilac.save()

                except Ilac.DoesNotExist:
                    return Response({'error': f'Ilac with ID {row["ILAC ID"]} not found.'},
                                    status=status.HTTP_400_BAD_REQUEST)

            return Response({'status': 'Ilac records created successfully'}, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({'error': f'An error occurred while processing the file: {str(e)}'},
                            status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['get'], url_path='get-detail-data')
    def get_detail_data(self, request):
        ilac_id = request.query_params.get('ilac_id')
        hastalik_id = request.query_params.get('hastalik_id')

        # İlac ID kontrolü
        if not ilac_id:
            return Response({'error': 'İlaç ID değeri sağlanamadı'}, status=status.HTTP_400_BAD_REQUEST)

        # Hastalık ID kontrolü
        if not hastalik_id:
            return Response({'error': 'Hastalık ID değeri sağlanamadı'}, status=status.HTTP_400_BAD_REQUEST)

        # Hastalık ve ilaç ile ilgili kilo doz bilgisini sorgulama
        kilodoz = HastalikHemYasaHemKiloyaBagliArtanDoz.objects.filter(
            ilac_id=ilac_id, hastaliklar_id=hastalik_id
        ).first()

        if not kilodoz:
            return Response({'error': 'Kilo doz bilgisi bulunamadı'}, status=status.HTTP_404_NOT_FOUND)

        # Sadece threshold_age alanını döndürmek
        return Response({'threshold_age': kilodoz.threshold_age}, status=status.HTTP_200_OK)










from .models import HastalikHemYasaHemKiloyaBagliAzalanDoz
from .serializers import HastalikHemYasaHemKiloyaBagliAzalanDozSerializers


class HastalikHemYasaHemKiloyaBagliAzalanDozViewSet(viewsets.ModelViewSet,BaseOlcekHesaplayici):
    queryset = HastalikHemYasaHemKiloyaBagliAzalanDoz.objects.all().order_by('id')
    serializer_class = HastalikHemYasaHemKiloyaBagliAzalanDozSerializers

    @action(detail=False, methods=['get'], url_path='get-hastalik-azalan-doz-hem-kilo-hem-yas')
    def get_hastalik_azalan_doz_hem_kilo_hem_yas(self, request):
        kilo = request.query_params.get('kilo',None)
        age = request.query_params.get('age')
        ilac_id = request.query_params.get('ilac_id')
        hastalik_id = request.query_params.get('hastalik_id')



        if not ilac_id:
            return Response({'error': 'İlaç ID değeri sağlanamadı'}, status=status.HTTP_400_BAD_REQUEST)

        if not hastalik_id:
            return Response({'error': 'Hastalık ID değeri sağlanamadı'}, status=status.HTTP_400_BAD_REQUEST)

        if not age:
            return Response({'error': 'age değeri sağlanamadı'}, status=status.HTTP_400_BAD_REQUEST)

        kilodoz = HastalikHemYasaHemKiloyaBagliAzalanDoz.objects.filter(ilac_id=ilac_id, hastaliklar_id=hastalik_id).first()

        if not kilodoz:
            return Response({'error': 'doz bilgisi bulunamadı'}, status=status.HTTP_404_NOT_FOUND)




        if kilodoz.threshold_age > int(age):

            if not kilo:
                return Response({'error': 'Kilo değeri sağlanmadı'}, status=status.HTTP_400_BAD_REQUEST)

            try:
                kilo = Decimal(str(kilo))
            except ValueError:
                return Response({'error': 'Kilo değeri geçersiz'}, status=status.HTTP_400_BAD_REQUEST)


            tipik_min_doz = kilodoz.tipik_min_doz or Decimal('0')
            tipik_max_doz = kilodoz.tipik_max_doz


            if tipik_max_doz is None:
                # Only minimum dose calculation
                if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                    min_doz = kilo * tipik_min_doz
                    min_kasik = (min_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                    min_kasik_mesaj = self.olcek_formatla(min_kasik)
                    doz_message = f"{min_kasik_mesaj} kullanın."
                else:
                    doz_message = f"{tipik_min_doz} ml kullanın."
            else:
                min_doz = kilo * tipik_min_doz
                maks_doz = kilo * tipik_max_doz

                if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                    min_kasik = (min_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                    min_kasik_mesaj = self.olcek_formatla(min_kasik)
                    maks_kasik = (maks_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                    maks_kasik_mesaj = self.olcek_formatla(maks_kasik)

                    if min_kasik_mesaj == maks_kasik_mesaj:
                        doz_message = f"{min_kasik_mesaj} kullanın."
                    else:
                        doz_message = f"{min_kasik_mesaj} veya {maks_kasik_mesaj} kullanın."
                else:
                    doz_message = f"{min_doz} ml veya {maks_doz} ml kullanın."

            response_data = {
                'message': doz_message,
                'kullanim_sikligi': kilodoz.kullanim_sikligi,
                'check_uyari': kilodoz.check_uyari,
            }
        else:
            min_doz = kilodoz.threshold_age_min_dose
            maks_doz = kilodoz.threshold_age_max_dose


            if min_doz is None and maks_doz is None:
                doz_message = "Kullanımı önerilmez."
            else:
                if maks_doz is None:
                    if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                        min_kasik = (min_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                        min_kasik_mesaj = self.olcek_formatla(min_kasik)
                        doz_message = f"{min_kasik_mesaj} kullanın."
                    else:
                        doz_message = f"{min_doz} ml kullanın."
                else:
                    if kilodoz.ilac.ilac_kategori.id in self.SPOON_ACCOUNTING_CATEGORIES:
                        min_kasik = (min_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                        min_kasik_mesaj = self.olcek_formatla(min_kasik)
                        maks_kasik = (maks_doz / self.KASIK_OLCEGI_ML).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
                        maks_kasik_mesaj = self.olcek_formatla(maks_kasik)

                        if min_kasik_mesaj == maks_kasik_mesaj:
                            doz_message = f"{min_kasik_mesaj} kullanın."
                        else:
                            doz_message = f"{min_kasik_mesaj} veya {maks_kasik_mesaj} kullanın."
                    else:
                        doz_message = f"{min_doz} ml veya {maks_doz} ml kullanın."

            response_data = {
                'message': doz_message,
                'kullanim_sikligi': kilodoz.kullanim_sikligi,
                'check_uyari': kilodoz.check_uyari,
            }

        return Response(response_data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['post'])
    def bulk_create_from_excel(self, request):
        file = request.FILES.get('file')
        if not file:
            return Response({'error': 'No file uploaded'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Excel dosyasını oku
            df = pd.read_excel(file)

            # Gerekli sütunların mevcut olup olmadığını kontrol et
            required_columns = ['Hastalık Ad','İLAÇ AD', 'durum','Yaş', 'ÜSTÜ','Kullanım sıklığı', 'Check Uyarı',
                                'TİPİK MİN DOZ', 'TİPİK MAX DOZ']

            if not all(column in df.columns for column in required_columns):

                return Response({
                    'error': 'Excel file must contain all required columns'
                }, status=status.HTTP_400_BAD_REQUEST)

            for _, row in df.iterrows():
                # Eğer 'durum' True ise (zaten işlenmiş), atla
                if row['durum'] == True:
                    continue

                try:
                    # İlgili Ilac nesnesini bul
                    ilac = Ilac.objects.get(name=row['İLAÇ AD'])

                    hastalik = Hastalik.objects.get(name=row['Hastalık Ad'])


                    # Konsantrasyon oranını hesapla
                    kontsantrasyon_orani = ilac.kontsantrasyon_mg / ilac.kontsantrasyon_ml

                    # Alanları kontrol et ve uygun şekilde işle
                    # Tipik min doz hesabı
                    tipik_min_doz = row['TİPİK MİN DOZ'] if pd.notna(row['TİPİK MİN DOZ']) else None
                    if tipik_min_doz is not None:
                        tipik_min_doz = Decimal(tipik_min_doz) / kontsantrasyon_orani

                    # Tipik max doz hesabı
                    tipik_max_doz = row['TİPİK MAX DOZ'] if pd.notna(row['TİPİK MAX DOZ']) else None
                    if tipik_max_doz is not None:
                        tipik_max_doz = Decimal(tipik_max_doz) / kontsantrasyon_orani


                    threshold_age_min_dose = Decimal('0')
                    threshold_age_max_dose = Decimal('0')

                    if pd.notna(row['ÜSTÜ']) and row['ÜSTÜ'].strip():
                        # Parse 'ALTI' list and convert values to Decimal
                        alti_list = row['ÜSTÜ'].strip('[]').split()
                        alti_list = [Decimal(x) for x in alti_list]

                        # Check if the list has at least 1 element
                        if len(alti_list) >= 1:
                            # Multiply the first element by 'kontsantrasyon_orani' and assign to min dose
                            threshold_age_min_dose = alti_list[0] / kontsantrasyon_orani


                        # Check if the list has a second element and assign to max dose
                        if len(alti_list) >= 2:
                            threshold_age_max_dose = alti_list[1] / kontsantrasyon_orani



                    check_uyari = row.get('Check Uyarı', '')
                    if pd.isna(check_uyari):
                        check_uyari = ''

                    # Yeni KiloDoz nesnesi oluştur
                    artankilodoz_data = {
                        'kullanim_sikligi': row['Kullanım sıklığı'],
                        'ilac': ilac,
                        'check_uyari': check_uyari,
                        'tipik_min_doz': tipik_min_doz,
                        'tipik_max_doz': tipik_max_doz,
                        'threshold_age': row['Yaş'],
                        'hastaliklar': hastalik
                    }

                    # Conditionally add min and max doses if they exist
                    if threshold_age_min_dose != Decimal('0'):
                        artankilodoz_data['threshold_age_min_dose'] = threshold_age_min_dose
                    if threshold_age_max_dose != Decimal('0'):
                        artankilodoz_data['threshold_age_max_dose'] = threshold_age_max_dose

                    # Create the ArtanKiloDoz instance
                    new_ilac = HastalikHemYasaHemKiloyaBagliAzalanDoz(**artankilodoz_data)

                    # Yeni nesneyi kaydet
                    new_ilac.save()

                except Ilac.DoesNotExist:
                    return Response({'error': f'Ilac with AD {row["ILAC AD"]} not found.'},
                                    status=status.HTTP_400_BAD_REQUEST)

                except Hastalik.DoesNotExist:
                    return Response({'error': f'Ilac with AD {row["Hastalık Ad"]} not found.'},
                                    status=status.HTTP_400_BAD_REQUEST)

            return Response({'status': 'Ilac records created successfully'}, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({'error': f'An error occurred while processing the file: {str(e)}'},
                            status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['get'], url_path='get-detail-data')
    def get_detail_data(self, request):
        ilac_id = request.query_params.get('ilac_id')
        hastalik_id = request.query_params.get('hastalik_id')

        # İlac ID kontrolü
        if not ilac_id:
            return Response({'error': 'İlaç ID değeri sağlanamadı'}, status=status.HTTP_400_BAD_REQUEST)

        # Hastalık ID kontrolü
        if not hastalik_id:
            return Response({'error': 'Hastalık ID değeri sağlanamadı'}, status=status.HTTP_400_BAD_REQUEST)

        # Hastalık ve ilaç ile ilgili kilo doz bilgisini sorgulama
        kilodoz = HastalikHemYasaHemKiloyaBagliAzalanDoz.objects.filter(
            ilac_id=ilac_id, hastaliklar_id=hastalik_id
        ).first()

        if not kilodoz:
            return Response({'error': 'bilgi bulunamadı'}, status=status.HTTP_404_NOT_FOUND)

        # Sadece threshold_age alanını döndürmek
        return Response({'threshold_age': kilodoz.threshold_age}, status=status.HTTP_200_OK)


# ------ besin takviyeleri ------

from .models import Supplement,ProductCategory,Product
from .serializers import SupplementSerializers,ProductCategorySerializers,ProductSerializers



class SupplementViewSet(viewsets.ModelViewSet):
    queryset = Supplement.objects.all().order_by('id')
    serializer_class = SupplementSerializers
    pagination_class = NoPagination




from django.shortcuts import get_object_or_404


class ProductCategoryViewSet(viewsets.ModelViewSet):
    queryset = ProductCategory.objects.all().order_by('id')
    serializer_class = ProductCategorySerializers
    pagination_class = NoPagination

    @action(detail=False, methods=['get'], url_path='list-categories-by-supplement')
    def list_categories_by_supplement(self, request):
        # supplement_id parametresini al
        supplement_id = request.query_params.get('supplement_id')

        if not supplement_id:
            return Response({"detail": "Supplement ID is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Supplement objesini güvenli bir şekilde getir
        supplement = get_object_or_404(Supplement, id=supplement_id)

        # İlgili kategorileri filtrele
        product_categories = ProductCategory.objects.filter(supplement=supplement)

        # Kategorileri serileştir
        serializer = self.get_serializer(product_categories, many=True)

        # Serileştirilmiş veriyi döndür
        return Response(serializer.data, status=status.HTTP_200_OK)


from rest_framework.exceptions import NotFound

class ProductViewSet(viewsets.ModelViewSet):
    queryset = Product.objects.all().order_by('id')
    serializer_class = ProductSerializers

    @action(detail=False, methods=['get'], url_path='list-products-by-category-no-paginations')
    def list_products_by_productcategory_no_paginations(self, request):
        # product_category_id parametresini al
        product_category_id = request.query_params.get('product_category_id')

        if not product_category_id:
            return Response({"detail": "product_category_id is required."}, status=status.HTTP_400_BAD_REQUEST)

        # product_category objesini güvenli bir şekilde getir
        product_category = get_object_or_404(ProductCategory, id=product_category_id)

        # İlgili kategorileri filtrele
        product = Product.objects.filter(product_category=product_category)

        # Kategorileri serileştir
        serializer = self.get_serializer(product, many=True)

        # Serileştirilmiş veriyi döndür
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'], url_path='list-products-by-category')
    def list_products_by_productcategory(self, request):
        # Get product_category_id from query params
        product_category_id = request.query_params.get('product_category_id')

        if not product_category_id:
            return Response({"detail": "product_category_id is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Retrieve the product category safely
        product_category = get_object_or_404(ProductCategory, id=product_category_id)

        # Filter products by the selected category
        product_queryset = Product.objects.filter(product_category=product_category)

        # Apply pagination to the queryset
        page = self.paginate_queryset(product_queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        # If pagination is not applied, return all products
        serializer = self.get_serializer(product_queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


    @action(detail=False, methods=['get'], url_path='product-detail')
    def product_detail(self, request):
        # Query parametresinden slug'ı al
        slug = request.query_params.get('slug')

        if not slug:
            return Response({"error": "Slug parametresi gerekli."}, status=400)

        try:
            # Slug'a göre ürünü al
            product = Product.objects.get(slug=slug)
        except Product.DoesNotExist:
            raise NotFound("Belirtilen slug ile eşleşen bir ürün bulunamadı.")

        # Serializer kullanarak ürünü döndür
        serializer = self.get_serializer(product)
        return Response(serializer.data)




from django.core.cache import cache


class CombinedView(APIView):
    def get(self, request):
        # Önbellekten verileri alıyoruz

        products = Product.objects.all().values('id', 'name')
        ilaclar = Ilac.objects.all().values('id', 'name', 'etken_madde', 'hassasiyet_turu_id')

        # Tüm Product nesneleri için sayfa alanı 'besin takviyesi' olacak
        product_list = list(products)
        for product in product_list:
            product['sayfa'] = 'besin takviyesi'
            product['etken_madde'] = ''
            product['hassasiyet_turu_id'] = ''


        # Tüm Ilac nesneleri için sayfa alanı 'ilac' olacak
        ilac_list = list(ilaclar)
        for ilac in ilac_list:
            ilac['sayfa'] = 'ilac'

        # İki listeyi birleştiriyoruz
        combined_data = product_list + ilac_list


        # Response ile JSON formatında geri döndürüyoruz
        return Response(combined_data, status=status.HTTP_200_OK)



# ------ hatırlatıcılar -----



from .models import Hatirlatici, HatirlaticiSaati, Bildirim
from .serializers import HatirlaticiSerializers, HatirlaticiSaatiSerializers, BildirimSerializers,HatirlaticiComplexSerializers
from django.utils.dateparse import parse_date
from django.db.models import Q
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated

class CustomPagination(PageNumberPagination):
    page_size = 10  # Set the default page size to 10


class HatirlaticiViewSet(viewsets.ModelViewSet):
    queryset = Hatirlatici.objects.all().order_by('-id')
    serializer_class = HatirlaticiSerializers
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        # Get the original data from the request
        data = request.data

        # Extract saat_listesi and remove it from the data sent to the serializer
        saat_listesi = data.pop('saat_listesi', None)

        # Pass the modified data to the serializer
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)

        # Create the Hatirlatici object
        hatirlatici = serializer.save()

        # If saat_listesi exists, create HatirlaticiSaati objects
        if saat_listesi:
            for saat in saat_listesi:
                HatirlaticiSaati.objects.create(hatirlatici=hatirlatici, saat=saat)



        # Return the response with the created hatirlatici
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)



    def list(self, request, *args, **kwargs):
        # Optimize queryset with prefetch_related
        queryset = self.get_queryset().prefetch_related('hatirlatici_saat')

        # Use Django Rest Framework's pagination
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        # Fallback to non-paginated response
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def retrieve(self, request, *args, **kwargs):
        # Optimize queryset with prefetch_related for a single object
        instance = self.get_object()
        instance = Hatirlatici.objects.prefetch_related('hatirlatici_saat').get(id=instance.id)
        serializer = self.get_serializer(instance)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'], url_path='user-active-reminders', pagination_class=CustomPagination)
    def user_active_reminders(self, request, *args, **kwargs):
        user = request.user
        date_str = request.query_params.get('date')

        if not date_str:
            return Response({"error": "Date parameter is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            date = parse_date(date_str)
            if not date:
                raise ValueError("Invalid date format")
        except ValueError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        active_reminders = Hatirlatici.objects.filter(
            user=user,
            baslangic_tarihi__lte=date,
            bitis_tarihi__gte=date,
            is_removed=False
        ).only('id', 'name', 'baslangic_tarihi', 'bitis_tarihi', 'is_removed', 'is_stopped').prefetch_related(
            'hatirlatici_saat').order_by('-id')

        # Use the custom pagination
        paginator = CustomPagination()
        page = paginator.paginate_queryset(active_reminders, request)
        if page is not None:
            serializer = HatirlaticiComplexSerializers(page, many=True)
            return paginator.get_paginated_response(serializer.data)

        # Use HatirlaticiComplexSerializers for full response
        serializer = HatirlaticiComplexSerializers(active_reminders, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)



    @action(detail=False, methods=['get'], url_path='user-inactive-reminders')
    def user_inactive_reminders(self, request, *args, **kwargs):
        user = request.user
        date_str = request.query_params.get('date')

        if not date_str:
            return Response({"error": "Date parameter is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            date = date_str
            if not date:
                raise ValueError("Invalid date format")
        except ValueError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        inactive_reminders = Hatirlatici.objects.filter(
            Q(baslangic_tarihi__gt=date) | Q(bitis_tarihi__lt=date),
            user=user
        ).prefetch_related('hatirlatici_saat').order_by('id')

        # Paginate results
        page = self.paginate_queryset(inactive_reminders)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(inactive_reminders, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['put'])
    def stoped(self, request, pk=None):
        hatirlatma = self.get_object()  # ID ile hatırlatıcıyı bul

        # `is_stopped` alanını True yap
        hatirlatma.is_stopped = True

        # Bitiş tarihini bugünün tarihi olarak ayarla
        hatirlatma.bitis_tarihi = timezone.now().date()

        # Değişiklikleri kaydet
        hatirlatma.save()

        # Değişiklikleri döndürmek için serializer kullan
        serializer = self.get_serializer(hatirlatma)
        return Response(serializer.data, status=status.HTTP_200_OK)

class HatirlaticiSaatiViewSet(viewsets.ModelViewSet):
    queryset = HatirlaticiSaati.objects.all().order_by('id')
    serializer_class = HatirlaticiSaatiSerializers
    pagination_class = NoPagination
    permission_classes = [IsAuthenticated]



class BildirimViewSet(viewsets.ModelViewSet):
    queryset = Bildirim.objects.all().order_by('id')
    serializer_class = BildirimSerializers
    permission_classes = [IsAuthenticated]

    @action(detail=False, methods=['get'], url_name='notifications-user-list')
    def notifications_user_list(self, request):
        user = request.user  # Get the user from the request

        # Filter notifications for the specific user
        notifications = Bildirim.objects.filter(hatirlatici__user=user).order_by('-tarih', '-saat').distinct()
        #print("notifications:",notifications)

        # Use the default paginator
        page = self.paginate_queryset(notifications)
        if page is not None:
            # If paginated, return paginated response
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        # If no pagination is applied, return all notifications
        serializer = self.get_serializer(notifications, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['post'], url_name='notifications-list-create')
    def notifications_list_create(self, request):
        # POST isteği ile gelen verileri alalım
        bildirim_list = request.data.get('bildirim_list')

        # Eğer bildirim_list yoksa ya da boşsa hata döndürelim
        if not bildirim_list or not isinstance(bildirim_list, list):
            return Response({"error": "bildirim_list eksik veya geçersiz formatta"}, status=400)

        # bildirim_list içindeki her bir nesneyi işleyelim
        for bildirim in bildirim_list:
            hatirlatici_id = bildirim.get('hatirlatici_id')
            explanations = bildirim.get('explanations')
            saat = bildirim.get('saat')
            tarih = bildirim.get('tarih')

            # Gerekli kontrolleri yapalım
            if not hatirlatici_id or not explanations or not saat:
                return Response({"error": "Eksik veri: hatirlatici_id, explanations veya saat eksik"}, status=400)

            Bildirim.objects.create(hatirlatici_id=hatirlatici_id,saat=saat,explanations=explanations,tarih=tarih)

        # Tüm bildirimler başarıyla işlendiğinde başarı yanıtı döndürelim
        return Response({"success": True}, status=200)
