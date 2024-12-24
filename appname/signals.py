# signals.py

from django.db.models.signals import post_save,post_delete
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from .models import Profile,Product,Ilac,Supplement,ProductCategory
from django.db.models.signals import post_migrate
import os
from django.conf import settings
import json
from django.db import connection

User = get_user_model()

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        # Create a profile with the user, leaving the photo field empty
        Profile.objects.create(user=instance)

"""

def load_json_file(file_path):

    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as file:
            return json.load(file)
    else:
        print(f"JSON dosyası bulunamadı: {file_path}")
        return None


@receiver(post_migrate)
def create_supplements_and_categories(sender, **kwargs):
    # 1. Tablonun var olup olmadığını kontrol et
    table_names = connection.introspection.table_names()
    if 'appname_product' in table_names:

        # 2. Supplement tablosu boşsa verileri ekle
        if not Supplement.objects.exists():
            # JSON dosyasının yolunu belirle
            json_file_path = os.path.join(settings.BASE_DIR, 'appname', 'products_data', 'ana_kategoriler.json')

            # JSON dosyasını aç ve oku
            with open(json_file_path, 'r', encoding='utf-8') as file:
                categories = json.load(file)

            # JSON dosyasındaki her kategori için Supplement nesnesi oluştur
            for category_name in categories:
                Supplement.objects.create(name=category_name)

            print(f"{len(categories)} kategori başarıyla Supplement tablosuna eklendi.")

        # 3. Vitaminler Supplement'ini bul
        if not ProductCategory.objects.exists():
            try:
                vitamin_supplement = Supplement.objects.get(name="Vitaminler")
            except Supplement.DoesNotExist:
                print("Vitaminler supplement'i bulunamadı.")
                return

            # 4. Vitaminler alt kategorilerini ekle
            category_json_path = os.path.join(settings.BASE_DIR, 'appname', 'products_data', 'vitaminler',
                                              'vitaminler_alt_kategori.json')

            if os.path.exists(category_json_path):
                with open(category_json_path, 'r', encoding='utf-8') as file:
                    subcategories = json.load(file)

                    # Alt kategorileri ekle
                    for subcategory_name in subcategories:
                        ProductCategory.objects.create(name=subcategory_name, supplement=vitamin_supplement)

                print(f"{len(subcategories)} alt kategori başarıyla ProductCategory tablosuna eklendi.")
            else:
                print(f"Alt kategori dosyası bulunamadı: {category_json_path}")

            # bitkisel ürünler
            try:
                bitkisel_urunler_supplement = Supplement.objects.get(name="Bitkisel Ürünler")
            except Supplement.DoesNotExist:
                print("bitkisel_urunler supplement'i bulunamadı.")
                return
            ProductCategory.objects.create(name='Bitkisel Ürünler', supplement=bitkisel_urunler_supplement)

            # minaraller
            try:
                minaraller_supplement = Supplement.objects.get(name="Minareller")
            except Supplement.DoesNotExist:
                print("minaraller supplement'i bulunamadı.")
                return
            ProductCategory.objects.create(name='Minarel', supplement=minaraller_supplement)

            # Glukozamin ve Eklem"
            try:
                glukozamin_ve_eklem_supplement = Supplement.objects.get(name="Glukozamin ve Eklem")
            except Supplement.DoesNotExist:
                print("glukozamin_ve_eklem supplement'i bulunamadı.")
                return
            ProductCategory.objects.create(name='Kolajen', supplement=glukozamin_ve_eklem_supplement)
            ProductCategory.objects.create(name='Hyalüronik Asit', supplement=glukozamin_ve_eklem_supplement)

            # Omega 3 / Balık Yağı"
            try:
                omega3_ve_balik_yagi_supplement = Supplement.objects.get(name="Omega 3 / Balık Yağı")
            except Supplement.DoesNotExist:
                print("omega3_ve_balik_yagi supplement'i bulunamadı.")
                return
            ProductCategory.objects.create(name='Omega 3 / Balık Yağı', supplement=omega3_ve_balik_yagi_supplement)

            # Probiyotik
            try:
                probiyotik_supplement = Supplement.objects.get(name="Probiyotik")
            except Supplement.DoesNotExist:
                print("Probiyotik supplement'i bulunamadı.")
                return
            ProductCategory.objects.create(name='Probiyotik', supplement=probiyotik_supplement)

        if not Product.objects.exists():

            #vitaminler
            vitamin_supplement = Supplement.objects.get(name="Vitaminler")
            products_vitaminler_json_path = os.path.join(settings.BASE_DIR, 'appname', 'products_data', 'vitaminler',
                                             'product_data_vitaminler.json')
            products_vitaminler = load_json_file(products_vitaminler_json_path)

            if products_vitaminler:
                for product in products_vitaminler:
                    category_name = product['alt_kategori']
                    product_category = ProductCategory.objects.filter(name=category_name,
                                                                      supplement=vitamin_supplement).first()

                    if product_category:
                        Product.objects.create(
                            name=product['title'],
                            product_category=product_category,
                            explanation=product['kullanim_sekli']
                        )
                print(f"{len(products_vitaminler)} ürün başarıyla Product tablosuna eklendi.")


            #minaraller
            minaral_supplement = Supplement.objects.get(name="Minareller")
            product_minaral_json_path = os.path.join(settings.BASE_DIR, 'appname', 'products_data', 'minaraller',
                                             'product_data_minaraller.json')
            products_minaraller = load_json_file(product_minaral_json_path)

            if products_minaraller:
                for product in products_minaraller:
                    category_name = product['alt_kategori']
                    product_category = ProductCategory.objects.filter(name=category_name,
                                                                      supplement=minaral_supplement).first()

                    if product_category:
                        Product.objects.create(
                            name=product['title'],
                            product_category=product_category,
                            explanation=product['kullanim_sekli']
                        )
                print(f"{len(products_minaraller)} ürün başarıyla Product tablosuna eklendi.")

            # probiyotik
            probiyotik_supplement = Supplement.objects.get(name="Probiyotik")
            probiyotik_json_path = os.path.join(settings.BASE_DIR, 'appname', 'products_data', 'probiyotik',
                                                     'product_data_probiyotik.json')
            products_probiyotik = load_json_file(probiyotik_json_path)

            if products_probiyotik:
                for product in products_probiyotik:
                    category_name = product['alt_kategori']
                    product_category = ProductCategory.objects.filter(name=category_name,
                                                                      supplement=probiyotik_supplement).first()

                    if product_category:
                        Product.objects.create(
                            name=product['title'],
                            product_category=product_category,
                            explanation=product['kullanim_sekli']
                        )
                print(f"{len(products_probiyotik)} ürün başarıyla Product tablosuna eklendi.")

            # omega3_balik_yagi
            omega3_balik_yagi_supplement = Supplement.objects.get(name="Omega 3 / Balık Yağı")
            omega3_balik_yagi_json_path = os.path.join(settings.BASE_DIR, 'appname', 'products_data', 'omega3_balik_yagi',
                                                     'product_data_omega3_balik_yagi.json')
            products_omega3_balik_yagi = load_json_file(omega3_balik_yagi_json_path)

            if products_omega3_balik_yagi:
                for product in products_omega3_balik_yagi:
                    category_name = product['alt_kategori']
                    product_category = ProductCategory.objects.filter(name=category_name,
                                                                      supplement=omega3_balik_yagi_supplement).first()

                    if product_category:
                        Product.objects.create(
                            name=product['title'],
                            product_category=product_category,
                            explanation=product['kullanim_sekli']
                        )
                print(f"{len(products_omega3_balik_yagi)} ürün başarıyla Product tablosuna eklendi.")

            # glukozamin_ve_eklem
            glukozamin_ve_eklem_supplement = Supplement.objects.get(name="Glukozamin ve Eklem")
            glukozamin_ve_eklem_json_path = os.path.join(settings.BASE_DIR, 'appname', 'products_data',
                                                       'glukozamin_ve_eklem',
                                                       'product_data_glukozamin_ve_eklem.json')
            products_glukozamin_ve_eklem = load_json_file(glukozamin_ve_eklem_json_path)

            if products_glukozamin_ve_eklem:
                for product in products_glukozamin_ve_eklem:
                    category_name = product['alt_kategori']
                    product_category = ProductCategory.objects.filter(name=category_name,
                                                                      supplement=glukozamin_ve_eklem_supplement).first()

                    if product_category:
                        Product.objects.create(
                            name=product['title'],
                            product_category=product_category,
                            explanation=product['kullanim_sekli']
                        )
                print(f"{len(products_glukozamin_ve_eklem)} ürün başarıyla Product tablosuna eklendi.")


            # bitkisel_urunler
            bitkisel_urunler_supplement = Supplement.objects.get(name="Bitkisel Ürünler")
            bitkisel_urunler_json_path = os.path.join(settings.BASE_DIR, 'appname', 'products_data',
                                                       'bitkisel_urunler',
                                                       'product_data_bitkisel_urunler.json')
            products_bitkisel_urunler = load_json_file(bitkisel_urunler_json_path)

            if products_bitkisel_urunler:
                for product in products_bitkisel_urunler:
                    category_name = product['alt_kategori']
                    product_category = ProductCategory.objects.filter(name=category_name,
                                                                      supplement=bitkisel_urunler_supplement).first()

                    if product_category:
                        Product.objects.create(
                            name=product['title'],
                            product_category=product_category,
                            explanation=product['kullanim_sekli']
                        )
                print(f"{len(products_bitkisel_urunler)} ürün başarıyla Product tablosuna eklendi.")



    else:
        print("ProductCategory tablosu henüz oluşturulmamış.")

"""
