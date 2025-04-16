import csv
import logging
import os
import re
import shutil
import sqlite3
import sys
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler

import pymupdf
import pytesseract
import pytz
from PIL import Image
from PyPDF2 import PdfMerger, PdfReader
from PyPDF2.errors import PdfReadError
from dotenv import load_dotenv
from thefuzz import fuzz
from watchdog.events import FileSystemEventHandler, DirCreatedEvent, FileCreatedEvent
from watchdog.observers import Observer

load_dotenv()

PATH_ARCHIVOS = os.getenv('PATH_ARCHIVOS')
PATH_SUCURSALES = os.getenv('PATH_SUCURSALES')
PROVEEDORES_CSV = os.getenv('PROVEEDORES_CSV')
SUCURSALES_CSV = os.getenv('SUCURSALES_CSV')
TESSERACT_PATH = os.getenv('TESSERACT_PATH')
DATABASE_PATH = os.getenv('DATABASE_PATH')
LOG_FILENAME = os.getenv('LOG_FILENAME')
try:
    LOG_SIZE_IN_BYTES = int(os.getenv('LOG_SIZE_IN_BYTES'))
except ValueError:
    LOG_SIZE_IN_BYTES = 1000000
try:
    NUMBER_OF_LOGS = int(os.getenv('NUMBER_OF_LOGS'))
except ValueError:
    NUMBER_OF_LOGS = 3
pytesseract.pytesseract.tesseract_cmd = TESSERACT_PATH

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.INFO)
stdout_handler.setFormatter(formatter)

file_handler = RotatingFileHandler(LOG_FILENAME,
                                   encoding='utf-8',
                                   maxBytes=LOG_SIZE_IN_BYTES,
                                   backupCount=NUMBER_OF_LOGS
                                   )
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(stdout_handler)


def get_proveedores_csv() -> []:
    proveedores = []
    try:
        with open(PROVEEDORES_CSV, newline='') as csvfile:
            csv_proveedores = csv.reader(csvfile, skipinitialspace=True)
            for row in csv_proveedores:
                dict_proveedor = {
                    'name': row[0],
                    'scan_name': row[1],
                }
                proveedores.append(dict_proveedor)
        return proveedores
    except FileNotFoundError:
        logger.error('No se encontro el archivo proveedores.csv')
        return []
    except Exception as e:
        logger.error(e)


def get_documento(nombre_documento: str, path_documento: str, visible: bool | None) -> {}:
    documento = {}
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        statement = '''SELECT d.id, d.name, d.current_path FROM documents_documents d where d.name = $1 and d.current_path = $2'''
        cursor_obj = conn.cursor()
        cursor_obj.execute(statement, [nombre_documento, path_documento])
        result_documento = cursor_obj.fetchone()
        if result_documento:
            documento = {
                'id': result_documento[0],
                'name': result_documento[1],
                'current_path': result_documento[2]
            }
    except sqlite3.Error as error:
        logger.error(error)
    except Exception as e:
        logger.error(e)
    finally:
        conn.close()
    return documento


def get_nombre_proveedor(path_documento: str) -> str | None:
    def get_encabezado(imagen):
        ancho, alto = imagen.size
        if ancho > alto:
            imagen = imagen.rotate(270, expand=True)
        alto2 = int(alto / 2)
        ancho2 = ancho
        imagen_encabezado = imagen.crop((0, 0, ancho2, alto2))
        return imagen, imagen_encabezado

    def get_seccion_contrarecibo(imagen):
        ancho, alto = imagen.size
        alto2 = int(alto / 2)
        ancho2 = ancho
        seccion_contrarecibo = imagen.crop((0, 0, ancho2, alto2))
        return seccion_contrarecibo

    def get_imagen_por_coordenadas(coordenadas, imagen):
        return imagen.crop(
            (coordenadas[0] - 5, coordenadas[1] - 5, int(imagen.size[0] / 2), coordenadas[1] + coordenadas[3] + 5))

    if os.path.exists(path_documento) and os.path.isfile(path_documento) and 'COMPLETO' not in path_documento:

        logger.debug(f'Obteniendo nombre de proveedor')
        nombre_scan_proveedor = None
        try:
            doc = pymupdf.open(path_documento)
            pix_images = [page.get_pixmap(dpi=300) for page in doc]
            paginas_pdf = []
            for imagen in pix_images:
                data = imagen.tobytes('ppm')
                img = Image.frombytes('RGB', (imagen.width, imagen.height), data)
                paginas_pdf.append(img)
        except Exception as e:
            logger.error(f'Error al obtener el nombre del proveedor {e}')
            return
        contrarecibo = None
        continuar = True
        for pagina in paginas_pdf:
            pagina, imagen_encabezado = get_encabezado(pagina)
            texto_encabezado = pytesseract.image_to_data(imagen_encabezado, output_type=pytesseract.Output.DICT,
                                                         config='--psm 12 --oem 3 -c tessedit_char_whitelist=CONTRARECIBO')
            for text in texto_encabezado['text']:
                if 'CONTRARECIBO' in text:
                    continuar = False
                    contrarecibo = pagina
                    break
            if not continuar:
                break

        if contrarecibo:
            seccion_contrarecibo = get_seccion_contrarecibo(contrarecibo)
            texto_contrarecibo = pytesseract.image_to_data(seccion_contrarecibo, output_type=pytesseract.Output.DICT,
                                                           lang='eng',
                                                           config='--psm 12 --oem 3 -c tessedit_char_whitelist=PROVEEDOR ')
            palabras_coordenadas = zip(texto_contrarecibo['left'], texto_contrarecibo['top'],
                                       texto_contrarecibo['width'], texto_contrarecibo['height'],
                                       texto_contrarecibo['text'])
            seccion_proveedor = None
            for palabra in palabras_coordenadas:
                if 'PROVEEDOR' in palabra[4]:
                    seccion_proveedor = palabra
                    break
            if seccion_proveedor:
                imagen_proveedor = get_imagen_por_coordenadas(seccion_proveedor, seccion_contrarecibo)
                texto_proveedor = pytesseract.image_to_data(imagen_proveedor, output_type=pytesseract.Output.DICT,
                                                            config='--psm 12 --oem 3 -c tessedit_char_blacklist=,.:;:')

                datos_proveedor = texto_proveedor['text']
                datos_proveedor = [x for x in datos_proveedor if len(x) > 0]
                indice_nombre_proveedor = -1
                for i, dato in enumerate(datos_proveedor):
                    match = re.search(r'(\d{4})', dato)
                    if match:
                        indice_nombre_proveedor = i + 1
                        break
                if indice_nombre_proveedor > -1:
                    nombre_proveedor = ''.join(datos_proveedor[indice_nombre_proveedor:])
                else:
                    nombre_proveedor = None
                # proveedores = get_proveedores()
                proveedores = get_proveedores_csv()
                nombres_proveedores = [x['name'] for x in proveedores]
                nombres_scan_proveedores = [x['scan_name'] for x in proveedores]

                if nombre_proveedor:
                    for k, nombre in enumerate(nombres_proveedores):
                        if fuzz.ratio(nombre.lower(), nombre_proveedor.replace(',', '').lower()) > 65:
                            nombre_scan_proveedor = nombres_scan_proveedores[k]
                else:
                    for dato in datos_proveedor:
                        if dato in nombres_scan_proveedores:
                            nombre_scan_proveedor = dato
                return nombre_scan_proveedor
            else:
                logger.debug(f'No se encontró el proveedor en el documento')
                return None
        else:
            logger.debug(f'No se encontró el contrarecibo en el documento')
            return None


def get_sucursal_csv(numero_serie: str) -> str | None:
    try:
        with open(SUCURSALES_CSV, newline='') as csvfile:
            csv_sucurlsales = csv.reader(csvfile, skipinitialspace=True)
            for row in csv_sucurlsales:
                if row[0] == numero_serie:
                    return row[1]
    except FileNotFoundError:
        logger.error('No se encontró el archivo equipos_sucursal.csv')
        return None
    except Exception as e:
        logger.error(f'Error al leer el archivo equipos_sucursal.csv: {e}')
        return None


def get_size(path_documento: str) -> int:
    try:
        with open(path_documento, "rb") as f:
            try:
                pdf_c = PdfReader(f, strict=False)
                return len(pdf_c.pages)
            except PdfReadError:
                logger.error('El archivo está vacío')
    except PermissionError:
        logger.error("No se puede leer el archivo, compruebe los permisos.")
    except FileNotFoundError:
        logger.error("No se encontró el archivo.")
    except Exception as e:
        logger.error(f'Error al leer el archivo: {e}')
    return 0


def insertar_en_base_de_datos(documento):
    logger.debug(f'Insertando en la base de datos')
    path_documento_completo = os.path.join(documento['current_path'], documento['name'])
    num_paginas = get_size(path_documento_completo)
    documento['size'] = num_paginas
    n_documento = insertar_documento(documento)
    if n_documento:
        logger.debug(f'El documento se insertó correctamente en la base de datos')
        log = {
            "log": f"Se creó el documento {n_documento['name']}.",
            "documents": n_documento['id']
        }
        insertar_log(log)
        return True
    else:
        logger.error(f'Error al insertar el documento en la base de datos')
        return False


def insertar_log(log: {}) -> bool:
    resultado = False
    datetime_now = datetime.now(pytz.timezone('UTC'))
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        statement = '''
                insert into logs_logs (log, documents_id,date) values ($1, $2, $3)
            '''
        cursor_obj = conn.cursor()
        cursor_obj.execute(statement, [log['log'], log['documents'], datetime_now.strftime('%Y-%m-%d %H:%M:%S')])
        conn.commit()
        if cursor_obj.rowcount == 1:
            resultado = True
    except sqlite3.Error as error:
        logger.error(error)
    finally:
        conn.close()
    return resultado


def insertar_documento(documento: {}) -> {}:
    documento_dic = {}
    datetime_now = datetime.now(pytz.timezone('UTC'))
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        statement = '''
                    insert into documents_documents (name, current_path, visible, size, uploaded_at) 
                    values ($1, $2, $3, $4, $5)
                    returning id, name, current_path, visible, size, uploaded_at
                '''
        cursor_obj = conn.cursor()
        cursor_obj.execute(statement, [documento['name'], documento['current_path'], documento['visible'],
                                       documento['size'], datetime_now.strftime('%Y-%m-%d %H:%M:%S')])
        result_documento = cursor_obj.fetchone()
        if result_documento:
            documento_dic = {
                'id': result_documento[0],
                'name': result_documento[1],
                'current_path': result_documento[2],
                'visible': result_documento[3],
                'size': result_documento[4],
                'uploaded_at': result_documento[5]
            }
        conn.commit()
    except sqlite3.Error as error:
        logger.error(error)
    except Exception as e:
        logger.error(f'Error desconocido {e}')
    finally:
        conn.close()
    return documento_dic


def update_ruta_documento(id_archivo: int, nueva_ruta: str) -> {}:
    documento_dic = {}
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        statement = """
                    update documents_documents 
                    set current_path = '{s2}'
                    where id = {s1}
                    returning id, name, current_path, visible, size, uploaded_at
                """.format(s1=id_archivo, s2=nueva_ruta)
        cursor_obj = conn.cursor()
        cursor_obj.execute(statement)
        result_documento = cursor_obj.fetchone()
        if result_documento:
            documento_dic = {
                'id': result_documento[0],
                'name': result_documento[1],
                'current_path': result_documento[2],
                'visible': result_documento[3],
                'size': result_documento[4],
                'uploaded_at': result_documento[5]
            }
        conn.commit()
    except sqlite3.Error as error:
        logger.error(error)
    finally:
        conn.close()
    return documento_dic


def update_size(documento: {}) -> {}:
    documento_dic = {}
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        statement = '''
                    update documents_documents 
                    set size = $1
                    where id = $2
                    returning id, name, current_path, visible, size, uploaded_at
                '''
        cursor_obj = conn.cursor()
        cursor_obj.execute(statement, [documento['size'], documento['id']])
        result_documento = cursor_obj.fetchone()
        if result_documento:
            documento_dic = {
                'id': result_documento[0],
                'name': result_documento[1],
                'current_path': result_documento[2],
                'visible': result_documento[3],
                'size': result_documento[4],
                'uploaded_at': result_documento[5]
            }
        conn.commit()
    except sqlite3.Error as error:
        logger.error(error)
    finally:
        conn.close()
    return documento_dic


def crea_paths(path_archivo: str, nombre_archivo: str) -> []:
    path_carpeta = path_archivo.replace(PATH_ARCHIVOS, '')
    nombre_carpeta = path_carpeta.split(os.sep)[1]
    fecha = ''
    flujo = ''
    numero_serie = ''
    sucursal = ''
    complemento_archivo = ''
    carpeta_superior = ''
    nuevo_path = ''
    nuevo_nombre = ''
    #### OBTIENE EL FLUJO
    try:
        flujo = nombre_carpeta.split('-')[1]
    except IndexError:
        logger.error('Flujo no encontrado')
        raise ValueError
    ### OBTIENE LA FECHA
    match = re.search(r'(\d{4}-\d{2}-\d{2})', nombre_archivo)
    if match:
        fecha = match.group(1)
    else:
        logger.error('Fecha no encontrada')
        raise ValueError
    ### OBTIENE EL NUMERO DE SERIE
    try:
        numero_serie = nombre_archivo.split('-')[0]
    except IndexError:
        logger.error('Nombre de archivo inválido')
        raise ValueError
    #### OBTIENE LA SUCURSAL
    sucursal = get_sucursal_csv(numero_serie)
    if not sucursal:
        logger.error('No se encontró la sucursal')
        raise ValueError
    ###Obtiene el año y mes desde la fecha que debe estar en formato yyyy-mm-dd
    lista_fecha = fecha.split('-')
    try:
        anio = lista_fecha[0]
        mes = lista_fecha[1]
    except IndexError:
        logger.error('Formato de fecha inválida.')
        raise ValueError
    #### Obtiene la extención del archivo
    try:
        complemento_archivo = nombre_archivo.split(fecha)[1]
    except IndexError:
        logger.error('Error al obtener la extensión del archivo')
        raise ValueError
    ### Obtiene el nombre de la carpeta en la que está el archivo
    try:
        carpeta_superior = path_carpeta.split(os.sep)[-2]
    except IndexError:
        logger.error('Error al obtener la carpeta superior')
        raise ValueError
    path_sucursal_flujo = os.path.join(PATH_SUCURSALES, f'{sucursal}-{flujo}')
    path_anio = os.path.join(path_sucursal_flujo, anio)
    path_mes = os.path.join(path_anio, mes)
    try:
        if not os.path.exists(path_sucursal_flujo):
            logger.debug(f'Creando carpeta {path_sucursal_flujo}')
            os.mkdir(path_sucursal_flujo)
        if not os.path.exists(path_anio):
            logger.debug(f'Creando carpeta {path_anio}')
            os.mkdir(path_anio)
        if not os.path.exists(path_mes):
            logger.debug(f'Creando carpeta {path_mes}')
            os.mkdir(path_mes)
    except PermissionError:
        logger.error('Error al crear las carpetas, no tiene permiso.')
        raise ValueError
    except FileExistsError:
        logger.error('Error al crear las carpetas, ya existen')
        raise ValueError
    except Exception as e:
        logger.error(f'Error desconocido {e}')
        raise ValueError
    if flujo == 'BANCOS':
        nuevo_path = path_mes
        nuevo_nombre = f'{sucursal}-{fecha}{complemento_archivo}'
    elif flujo == 'CUENTAS POR PAGAR':
        if carpeta_superior == 'DEVOLUCIONES':
            try:
                nuevo_path = os.path.join(path_mes, carpeta_superior)
                nuevo_nombre = f'{sucursal}-{fecha}{complemento_archivo}'
                if not os.path.exists(nuevo_path):
                    os.mkdir(nuevo_path)
                    logger.debug(f'Creando carpeta {nuevo_path}')
            except PermissionError:
                logger.error('Error al crear las carpetas, no tiene permiso.')
                raise ValueError
            except FileExistsError:
                logger.error('Error al crear las carpetas, ya existe el archivo.')
                raise ValueError
            except Exception as e:
                logger.error(f'Error desconocido {e}')
                raise ValueError
        elif carpeta_superior == 'FACTURAS Y CONTRARECIBOS':
            try:
                nombre_proveedor = get_nombre_proveedor(path_archivo)
                if nombre_proveedor:
                    logger.debug(f'Se encontró el nombre del proveedor {nombre_proveedor}')
                    nuevo_nombre = f'{sucursal}-{nombre_proveedor}-{fecha}{complemento_archivo}'
                else:
                    logger.debug(f'No se encontró el nombre del proveedor.')
                    nuevo_nombre = f'{sucursal}-{fecha}{complemento_archivo}'
            except ValueError:
                logger.error('Error al obtener el nombre del proveedor')
                raise ValueError
            try:
                nuevo_path = os.path.join(path_mes, carpeta_superior)
                if not os.path.exists(nuevo_path):
                    os.mkdir(nuevo_path)
                    logger.debug(f'Creando carpeta {nuevo_path}')
            except PermissionError:
                logger.error('Error al crear las carpetas, no tiene permiso.')
                raise ValueError
            except FileExistsError:
                logger.error('Error al crear las carpetas, ya existe el archivo.')
                raise ValueError
            except Exception as e:
                logger.error(f'Error desconocido {e}')
                raise ValueError
    elif flujo == 'GASTOS':
        match_incompleto = re.search(r'(\d{6}).pdf', nombre_archivo)
        extension_incompleto = '.pdf'
        if match_incompleto:
            extension_incompleto = f'_{match_incompleto.group(1)}.pdf'
        if carpeta_superior == 'COMPRAS DE MERCANCIA':
            nuevo_path = os.path.join(path_mes, carpeta_superior)
            nuevo_nombre = f'{sucursal}-COMPRA-{fecha}{extension_incompleto}'
            try:
                if not os.path.exists(nuevo_path):
                    os.mkdir(nuevo_path)
                    logger.debug(f'Creando carpeta {nuevo_path}')
            except PermissionError:
                logger.error('Error al crear las carpetas, no tiene permiso.')
                raise ValueError
            except FileExistsError:
                logger.error('Error al crear las carpetas, ya existe el archivo.')
                raise ValueError
            except Exception as e:
                logger.error(f'Error desconocido {e}')
                raise ValueError
        elif carpeta_superior == 'GASTOS OPERATIVOS':
            nuevo_path = os.path.join(path_mes, carpeta_superior)
            nuevo_nombre = f'{sucursal}-GASTO-{fecha}{complemento_archivo}'
            try:
                if not os.path.exists(nuevo_path):
                    os.mkdir(nuevo_path)
                    logger.debug(f'Creando carpeta {nuevo_path}')
            except PermissionError:
                logger.error('Error al crear las carpetas, no tiene permiso.')
                raise ValueError
            except FileExistsError:
                logger.error('Error al crear las carpetas, ya existe el archivo.')
                raise ValueError
            except Exception as e:
                logger.error(f'Error desconocido {e}')
                raise ValueError

    return [nuevo_nombre, nuevo_path, flujo, sucursal]


def mueve_archivo(path_archivo_origen: str, path_archivo_destino: str, overwrite: bool) -> str:
    def number_generator(path: str, numbers=100000, length=6) -> str:
        directorio, archivo = os.path.split(path_archivo_destino)
        nombre_archivo, extension = os.path.splitext(archivo)
        for i in range(1, 100000):
            path_aux = os.path.join(directorio, f'{nombre_archivo}_{i:0{length}}{extension}')
            if not os.path.exists(path_aux):
                return path_aux

    if not overwrite and os.path.exists(path_archivo_destino):
        path_archivo_destino = number_generator(path_archivo_destino)

    try:
        shutil.move(path_archivo_origen, path_archivo_destino)
        return path_archivo_destino
    except PermissionError:
        logger.error('Error. No se puede mover el archivo, compruebe los permisos.')
        time.sleep(3)
        logger.info('Intentando mover el archivo nuevamente')
        try:
            shutil.move(path_archivo_origen, path_archivo_destino)
            return path_archivo_destino
        except Exception as e:
            logger.error('Error. No se puede mover el archivo, compruebe los permisos.')
    except FileNotFoundError:
        logger.error('No se encontró el archivo.')
    except shutil.Error:
        logger.error('Ya existe el archivo.')
    return ''


def unir_documentos(path_destino: str, path_nuevo_archivo: str) -> bool:
    logger.info('Uniendo documentos')
    resultado = False
    try:
        merger = PdfMerger()
        merger.append(path_destino)
        merger.append(path_nuevo_archivo)
        merger.write(path_destino)
        resultado = True
    except Exception as e:
        logger.error(f'Error al unir el documento {e}')
    finally:
        merger.close()
        return resultado


def eliminar_archivo(path_archivo: str) -> bool:
    resultado = False
    try:
        os.remove(path_archivo)
        resultado = True
    except PermissionError:
        logger.error('No se pudo eliminar el archivo, compruebe los permisos.')
    except FileNotFoundError:
        logger.error('No se encontró el archivo a eliminar.')
    return resultado


class FileObserver(FileSystemEventHandler):

    def on_created(self, event: DirCreatedEvent | FileCreatedEvent) -> None:
        if isinstance(event, FileCreatedEvent):
            if not PATH_SUCURSALES in event.src_path:
                path_nuevo_archivo = event.src_path
                ruta_archivo, nombre_archivo = os.path.split(path_nuevo_archivo)
                nombre, extension = os.path.splitext(nombre_archivo)
                logging.info(f"nuevo archivo {path_nuevo_archivo}")
                if extension.lower() != '.pdf':
                    logger.info('Omitiendo archivo')
                    return
                else:
                    try:
                        [nombre, nuevo_path, flujo, sucursal] = crea_paths(path_nuevo_archivo, nombre_archivo)
                    except ValueError:
                        logger.error('No se pudo crear el path.')
                        return
                    if flujo in ['BANCOS', 'CUENTAS POR PAGAR']:
                        path_destino = os.path.join(nuevo_path, nombre)
                        path = mueve_archivo(path_nuevo_archivo, path_destino, overwrite=False)
                        if path:
                            current_path, name = os.path.split(path)
                            doc = {
                                'name': name,
                                'current_path': current_path,
                                'visible': True,
                            }
                            insertar_en_base_de_datos(doc)
                    elif flujo == 'GASTOS':
                        path_destino = os.path.join(nuevo_path, nombre)
                        if os.path.exists(path_destino):
                            resultado_unir = unir_documentos(path_destino, path_nuevo_archivo)
                            if resultado_unir:
                                current_path, name = os.path.split(path_destino)
                                doc = get_documento(name, current_path, visible=True)
                                if doc:
                                    doc['size'] = get_size(path_destino)
                                    update_size(doc)
                                    _path, archivo_unido = os.path.split(path_nuevo_archivo)
                                    log = {
                                        'log': f'Se unió el documento {archivo_unido}',
                                        'documents': doc['id']
                                    }
                                    insertar_log(log)
                                eliminar_archivo(path_nuevo_archivo)

                        else:
                            path = mueve_archivo(path_nuevo_archivo, path_destino, overwrite=True)
                            if path:
                                doc = {
                                    'name': nombre,
                                    'current_path': nuevo_path,
                                    'visible': True,
                                }
                                insertar_en_base_de_datos(doc)
                    else:
                        logger.error('Flujo desconocido.')
                        return
                logger.debug(f'Se procesó el documento {path_nuevo_archivo}')


if __name__ == "__main__":
    event_handler = FileObserver()
    observer = Observer()
    observer.schedule(event_handler, path=PATH_ARCHIVOS, recursive=True)
    observer.start()
    logger.info('Observando directorio: %s', PATH_ARCHIVOS)
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        observer.stop()
    finally:
        observer.join()
