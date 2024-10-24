from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from .models import CustomUser,Profile
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.core.validators import validate_email as django_validate_email
from django.contrib.auth import get_user_model


User = get_user_model()

class CustomUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = CustomUser
        fields = ('id', 'email', 'password', 'first_name', 'last_name')

    def validate(self, attrs):
        password = attrs.get('password')
        if password and len(password) < 8:
            raise serializers.ValidationError({"password": "Şifreniz en az 8 karakter uzunluğunda olmalıdır."})
        return attrs

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        user = CustomUser(**validated_data)
        if password:
            user.set_password(password)
        user.save()
        return user

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if password:
            instance.set_password(password)
        instance.save()
        return instance


class ProfileSerilizers(serializers.ModelSerializer):
    user_first_name = serializers.CharField(allow_blank=True, required=False)
    user_last_name = serializers.CharField(allow_blank=True, required=False)
    user = CustomUserSerializer(read_only=True)

    class Meta:
        model = Profile
        fields = '__all__'

    def update(self, instance, validated_data):



        # Extract user-specific data before updating profile fields
        user_first_name = validated_data.pop('user_first_name', None)
        user_last_name = validated_data.pop('user_last_name', None)

        # Update other profile fields
        for attr, value in validated_data.items():   # gelen verileri insanceye kayıt eder. x alanı var gelen verı, o degerı bu alana gecırır. toplu ıslemn saglıyor.
            setattr(instance, attr, value)

        # Save the profile instance
        instance.save()

        # Update the associated user instance if user data is provided
        if user_first_name is not None or user_last_name is not None:
            user = instance.user
            if user:
                if user_first_name is not None:
                    user.first_name = user_first_name
                if user_last_name is not None:
                    user.last_name = user_last_name
                user.save()

        return instance


# ------ ilaç ------

from .models import IlacKategori,Ilac,HassasiyetTuru,Form,Hastalik,YasDoz,KiloDoz,ExplanationDoz,HatalikYasDoz,HastalikKiloDoz,\
    ArtanKiloDoz,AzalanKiloDoz,HastalikArtanKiloDoz,HastalikAzalanKiloDoz,HastalikHemYasaHemKiloyaBagliArtanDoz,HastalikHemYasaHemKiloyaBagliAzalanDoz

class IlacKategoriSerializers(serializers.ModelSerializer):

    class Meta:
        model = IlacKategori
        fields = '__all__'


class HassasiyetTuruSerializers(serializers.ModelSerializer):

    class Meta:
        model = HassasiyetTuru
        fields = '__all__'


class HastalikSerializers(serializers.ModelSerializer):
    class Meta:
        model = Hastalik
        fields = '__all__'

class HassasiyetTuruNameSerializer(serializers.ModelSerializer):
    class Meta:
        model = HassasiyetTuru
        fields = ['id']

class FormSerializers(serializers.ModelSerializer):
    class Meta:
        model = Form
        fields = '__all__'


class IlacDetailSerializer(serializers.ModelSerializer):
    ilac_kategori = IlacKategoriSerializers(read_only=True)
    hassasiyet_turu = HassasiyetTuruSerializers(read_only=True)
    hastaliklar = HastalikSerializers(many=True, read_only=True)
    ilac_form = FormSerializers(read_only=True)

    class Meta:
        model = Ilac
        fields = ['id', 'name', 'etken_madde', 'kullanim_uyarisi', 'document', 'ilac_kategori','ilac_form', 'hassasiyet_turu', 'hastaliklar']




class IlacListSerializer(serializers.ModelSerializer):
    hassasiyet_turu = HassasiyetTuruNameSerializer(read_only=True)
    class Meta:
        model = Ilac
        fields = ['id', 'name', 'etken_madde','hassasiyet_turu']  # Sadece gerekli alanlar


class YasDozSerializers(serializers.ModelSerializer):
    #ilac = IlacSerializers(read_only=True)

    class Meta:
        model = YasDoz
        fields = '__all__'

class YasDozDetailSerializers(serializers.ModelSerializer):
    class Meta:
        model = YasDoz
        fields = ['id', 'doz']  # Sadece gerekli alanlar


class KiloDozSerializers(serializers.ModelSerializer):
    #ilac = IlacSerializers(read_only=True)

    class Meta:
        model = KiloDoz
        fields = '__all__'



class ExplanationDozSerializers(serializers.ModelSerializer):
    #ilac = IlacSerializers(read_only=True)

    class Meta:
        model = ExplanationDoz
        fields = '__all__'



class ExplanationDetailDozSerializers(serializers.ModelSerializer):
    class Meta:
        model = ExplanationDoz
        fields = ['id', 'bilgi']  # Sadece gerekli alanlar


class HatalikYasDozSerializers(serializers.ModelSerializer):
    #ilac = IlacSerializers(read_only=True)

    class Meta:
        model = HatalikYasDoz
        fields = '__all__'


class HatalikYasDozDetailSerializers(serializers.ModelSerializer):
    class Meta:
        model = HatalikYasDoz
        fields = ['id', 'doz']  # Sadece gerekli alanlar


class HastalikKiloDozSerializers(serializers.ModelSerializer):
    #ilac = IlacSerializers(read_only=True)

    class Meta:
        model = HastalikKiloDoz
        fields = '__all__'


class ArtanKiloDozSerializers(serializers.ModelSerializer):
    #ilac = IlacSerializers(read_only=True)

    class Meta:
        model = ArtanKiloDoz
        fields = '__all__'

class AzalanKiloDozSerializers(serializers.ModelSerializer):
    #ilac = IlacSerializers(read_only=True)

    class Meta:
        model = AzalanKiloDoz
        fields = '__all__'


class HastalikArtanKiloDozSerializers(serializers.ModelSerializer):
    #ilac = IlacSerializers(read_only=True)

    class Meta:
        model = HastalikArtanKiloDoz
        fields = '__all__'




class HastalikAzalanKiloDozSerializers(serializers.ModelSerializer):
    #ilac = IlacSerializers(read_only=True)

    class Meta:
        model = HastalikAzalanKiloDoz
        fields = '__all__'



class HastalikHemYasaHemKiloyaBagliArtanDozSerializers(serializers.ModelSerializer):
    #ilac = IlacSerializers(read_only=True)

    class Meta:
        model = HastalikHemYasaHemKiloyaBagliArtanDoz
        fields = '__all__'




class HastalikHemYasaHemKiloyaBagliAzalanDozSerializers(serializers.ModelSerializer):
    #ilac = IlacSerializers(read_only=True)

    class Meta:
        model = HastalikHemYasaHemKiloyaBagliAzalanDoz
        fields = '__all__'


# ------ besin takviyeleri ------

from .models import Supplement,ProductCategory,Product


class SupplementSerializers(serializers.ModelSerializer):

    class Meta:
        model = Supplement
        fields = '__all__'


class ProductCategorySerializers(serializers.ModelSerializer):

    class Meta:
        model = ProductCategory
        fields = '__all__'


class ProductSerializers(serializers.ModelSerializer):

    class Meta:
        model = Product
        fields = '__all__'


# ------ hatırlatıcılar -----

from .models import Hatirlatici, HatirlaticiSaati, Bildirim



class HatirlaticiJoinSaatiSerializers(serializers.ModelSerializer):

    class Meta:
        model = HatirlaticiSaati
        fields = ['id', 'saat']


class HatirlaticiSerializers(serializers.ModelSerializer):


    class Meta:
        model = Hatirlatici
        fields = '__all__'

    def create(self, validated_data):
        request = self.context.get('request')  # Request objesini al
        user = request.user  # Kullanıcı bilgisine eriş
        print("validate:",validated_data)
        hatirlatici = Hatirlatici.objects.create(user=user, **validated_data)

        return hatirlatici



class HatirlaticiComplexSerializers(serializers.ModelSerializer):
    hatirlatici_saat = HatirlaticiJoinSaatiSerializers(many=True, read_only=True)


    class Meta:
        model = Hatirlatici
        fields = ['id', 'name', 'baslangic_tarihi','bitis_tarihi','is_removed','is_stopped','hatirlatici_saat']

    def create(self, validated_data):
        request = self.context.get('request')  # Request objesini al
        user = request.user  # Kullanıcı bilgisine eriş
        hatirlatici = Hatirlatici.objects.create(user=user, **validated_data)

        return hatirlatici




class HatirlaticiSaatiSerializers(serializers.ModelSerializer):

    class Meta:
        model = HatirlaticiSaati
        fields = '__all__'


class BildirimSerializers(serializers.ModelSerializer):

    class Meta:
        model = Bildirim
        fields = '__all__'