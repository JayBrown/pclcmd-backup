#!/usr/bin/env python
# -*- coding: utf-8 -*-

__title__    = "pclcmd"
__version__  = "0.2"
__author__   = "Anton Batenev"
__license__  = "BSD"


import array, random
import os, sys, errno
import socket, ssl
import re, codecs, json
import time, datetime
import hashlib, shutil


try:
    import dateutil.parser
    import dateutil.relativedelta

    # Hide UnicodeWarning in dateutil under Windows
    # https://bugs.launchpad.net/dateutil/+bug/1227221
    if os.name == "nt":
        import warnings
        warnings.filterwarnings("ignore", category = UnicodeWarning)

except ImportError:
    sys.stderr.write("Python module dateutil not found.\nPlease, install \"python-dateutil\"\n")
    sys.exit(1)


# suggests
try:
    import progressbar as pclProgressBar
except:
    pclProgressBar = None


# PEP-8
try:
    import configparser
except ImportError:
    import ConfigParser as configparser


# PEP-469
try:
    dict.iteritems
except AttributeError:
    def itervalues(d):
        return iter(d.values())
    def iteritems(d):
        return iter(d.items())
    def listvalues(d):
        return list(d.values())
    def listitems(d):
        return list(d.items())
else:
    def itervalues(d):
        return d.itervalues()
    def iteritems(d):
        return d.iteritems()
    def listvalues(d):
        return d.values()
    def listitems(d):
        return d.items()


# PEP-3108
try:
    from http.client    import HTTPSConnection   as pclHTTPSConnectionBase
    from http.client    import NotConnected      as pclNotConnected
    from http.client    import BadStatusLine     as pclBadStatusLine
    from http.client    import CannotSendRequest as pclCannotSendRequest
    from urllib.request import HTTPSHandler      as pclHTTPSHandlerBase
    from urllib.request import Request           as pclRequest
    from urllib.request import build_opener      as pcl_build_opener
    from urllib.error   import HTTPError         as pclHTTPError
    from urllib.error   import URLError          as pclURLError
    from urllib.parse   import urlencode         as pcl_urlencode
except ImportError:
    from httplib        import HTTPSConnection   as pclHTTPSConnectionBase
    from httplib        import NotConnected      as pclNotConnected
    from httplib        import BadStatusLine     as pclBadStatusLine
    from httplib        import CannotSendRequest as pclCannotSendRequest
    from urllib2        import HTTPSHandler      as pclHTTPSHandlerBase
    from urllib2        import Request           as pclRequest
    from urllib2        import build_opener      as pcl_build_opener
    from urllib2        import HTTPError         as pclHTTPError
    from urllib2        import URLError          as pclURLError
    from urllib         import urlencode         as pcl_urlencode


class pclError(RuntimeError):
    """
    Внутреннее исключение, выбрасываемое в случаях:
        * Таймаут запроса к API
        * Исчерпание количества попыток запроса к API
        * Неверные аргументы, переданные в командной строке
    """
    def __init__(self, errno, errmsg):
        """
        Аргументы:
            errno  (int) -- Код ошибки (аналог кода возврата)
            errmsg (str) -- Текст ошибки
        """
        self.errno  = errno
        self.errmsg = "{0}".format(errmsg)

        # http://bugs.python.org/issue1692335
        self.args = (errno, errmsg)


    def __str__(self):
        return self.errmsg


class pclCertError(ValueError):
    """
    Исключение при проверке валидности SSL сертификата
    """
    pass


class pclHTTPSConnection(pclHTTPSConnectionBase):
    """
    Сабклассинг pclHTTPSConnectionBase для:
        * Проверки валидности SSL сертификата
        * Установки предпочитаемого набора шифров / алгоритма шифрования
        * Задания размера отсылаемого блока
    """
    def __init__(self, host, **kwargs):
        """
        Дополнительные аргументы:
            options (pclOptions) -- Опции приложения
        """
        self._options = kwargs.pop("options", None)
        pclHTTPSConnectionBase.__init__(self, host, **kwargs)


    @staticmethod
    def _check_cert(cert, hostname):
        """
        Проверка валидности SSL сертификата

        Аргументы:
            cert     (dict) -- Данные сертификата
            hostname (str)  -- Имя хоста

        Исключения:
            pclCertError в случае ошибки проверки валидности сертификата
            (подробнее см. https://gist.github.com/zed/1347055)
        """
        def _dns(dn):
            pats = []
            for frag in dn.split(r"."):
                if frag == '*':
                    pats.append("[^.]+")
                else:
                    frag = re.escape(frag)
                    pats.append(frag.replace(r"\*", "[^.]*"))
            return re.compile(r"\A" + r"\.".join(pats) + r"\Z", re.IGNORECASE)


        if not cert:
            raise ValueError("Empty or no certificate")

        notafter = cert.get("notAfter", None)
        if notafter == None:
            raise pclCertError("No appropriate notAfter field were found in certificate")

        try:
            expire = dateutil.parser.parse(notafter).astimezone(dateutil.tz.tzutc())
        except:
            raise pclCertError("Can not parse cirtificate notAfter field")

        if expire < datetime.datetime.now(dateutil.tz.tzutc()).replace(microsecond = 0):
            raise pclCertError("Cirtificate expired at {0}".format(notafter))

        san      = cert.get("subjectAltName", ())
        dnsnames = []

        for key, value in san:
            if key == "DNS":
                if _dns(value).match(hostname):
                    return
                dnsnames.append(value)

        if not dnsnames:
            for sub in cert.get("subject", ()):
                for key, value in sub:
                    if key == "commonName":
                        if _dns(value).match(hostname):
                            return
                        dnsnames.append(value)

        if len(dnsnames) > 1:
            raise pclCertError("Certificate hostname {0!r} doesn't match either of {1!s}".format(hostname, ", ".join(map(repr, dnsnames))))
        elif len(dnsnames) == 1:
            raise pclCertError("Certificate hostname {0!r} doesn't match {1!r}".format(hostname, dnsnames[0]))
        else:
            raise pclCertError("No appropriate commonName or subjectAltName fields were found in certificate")


    def connect(self):
        """
        Перегрузка pclHTTPSConnectionBase.connect для проверки валидности SSL сертификата
        и установки предпочитаемого набора шифров / алгоритма шифрования
        """
        sock = socket.create_connection((self.host, self.port), self.timeout)

        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        if getattr(self, "_tunnel_host", None):
            self.sock = sock
            self._tunnel()

        kwargs = {}
        if self._options.cafile != None:
            kwargs.update (
                cert_reqs = ssl.CERT_REQUIRED,
                ca_certs  = self._options.cafile
            )

        if self._options.ciphers != None and pcl_check_python23(7, 0, 2, 0):   # Python >= 2.7 / 3.2
            kwargs.update(ciphers = self._options.ciphers)

        sslv3_workaround = pcl_check_python23(7, 9, 2, 0)   # Python >= 2.7.9 / 3.2
        if sslv3_workaround:
            kwargs.update(ssl_version = ssl.PROTOCOL_SSLv23)
        else:
            kwargs.update(ssl_version = ssl.PROTOCOL_TLSv1)

        self.sock = ssl.wrap_socket(sock, keyfile = self.key_file, certfile = self.cert_file, **kwargs)

        if sslv3_workaround:
            self.sock.context.options |= ssl.OP_NO_SSLv2
            self.sock.context.options |= ssl.OP_NO_SSLv3

        if self._options.debug:
            ciphers = self.sock.cipher()
            pcl_debug("Connected to {0}:{1} ({2} {3})".format(self.host, self.port, self.sock.version() if pcl_check_python23(7, 9, 5, 0) else ciphers[1], ciphers[0]))

        if self._options.cafile != None:
            try:
                self._check_cert(self.sock.getpeercert(), self.host)
            except pclCertError:
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
                raise


    def request(self, method, url, body = None, headers = {}, **kwargs):
        """
        Перегрузка pclHTTPSConnectionBase.request для сохранения Content-Length отправляемого файла
        """
        self._content_length = headers["Content-Length"] if "Content-Length" in headers else None
        self._send_request(method, url, body, headers, **kwargs)


    def upload(self, data):
        """
        Отправка данных в хранилище (вынесено из send)
        """
        if options.progress:
            written = 0
            start   = int(time.time())
            bar     = None

            try:
                total = int(self._content_length)
                if pclProgressBar:
                    try:
                        widgets = ["--> Upload: ", pclProgressBar.Percentage(), " ", pclProgressBar.Bar(left = "[", marker = "=", right = "]"), " ", pclProgressBar.ETA(), " ", pclProgressBar.FileTransferSpeed()]
                        bar = pclProgressBar.ProgressBar(widgets = widgets, maxval = total).start()
                    except:
                        total = pcl_human(total)
                else:
                    total = pcl_human(total)
            except:
                total = "-"

        datablock = data.read(self._options.chunk)

        while datablock:
            self.sock.sendall(datablock)

            if self._options.progress:
                written += len(datablock)
                if bar:
                    bar.update(written)
                else:
                    delta = int(time.time()) - start
                    if delta > 0:
                        sys.stderr.write("--> Upload: {0}/{1} ({2}/s){3}\r".format(pcl_human(written), total, pcl_human(written / delta), " " * 12))

            datablock = data.read(self._options.chunk)

        if self._options.progress:
            if bar:
                bar.finish()
            else:
                sys.stderr.write("{0}\r".format(" " * 33))


    def send(self, data):
        """
        Перегрузка pclHTTPSConnectionBase.send для возможности задания размера отсылаемого блока
        """
        if self.sock is None:
            if self.auto_open:
                self.connect()
            else:
                raise pclNotConnected()

        if hasattr(data, "read") and not isinstance(data, array.array):
            self.upload(data)
        else:
            self.sock.sendall(data)


class pclHTTPSHandler(pclHTTPSHandlerBase):
    """
    Сабклассинг pclHTTPSHandlerBase для:
        * Проверки валидности SSL сертификата
        * Установки предпочитаемого набора шифров / алгоритма шифрования
        * Задания размера отсылаемого блока
    """
    def __init__(self, options, debuglevel = 0):
        """
        Аргументы:
            options (pclOptions) -- Опции приложения
        """
        self._options = options

        pclHTTPSHandlerBase.__init__(self, debuglevel)


    def https_open(self, req):
        """
        Перегрузка pclHTTPSHandlerBase.https_open для использования pclHTTPSConnection
        """
        return self.do_open(self._get_connection, req)


    def _get_connection(self, host, **kwargs):
        """
        Callback создания pclHTTPSConnection
        """
        d = { "options" : self._options }
        d.update(kwargs)

        return pclHTTPSConnection(host, **d)


def pcl_default_config():
    """
    Получение конфигурации приложения по умолчанию

    Результат (dict):
        Конфигурация приложения по умолчанию, которая может быть перегружена в вызове pcl_load_config
    """
    result = {
        "timeout"          : "30",
        "retries"          : "3",
        "delay"            : "30",
        "chunk"            : "512",   # default mdadm chunk size and optimal read-ahead is 512KB
        "token"            : "",
        "quiet"            : "no",
        "verbose"          : "no",
        "debug"            : "no",
        "rsync"            : "no",
        "no-recursion"     : "no",
        "no-recursion-tag" : "",
        "exclude-tag"      : "",
        "skip-hash"        : "no",
        "progress"         : "no",
        "iconv"            : "",
        "base-url"         : "https://api.pcloud.com",
        "app-id"           : "P8RcYvRXB1p",
        "app-secret"       : "uvrkmetjrmpERcqNn3MWTSHR2dSk",
        "ca-file"          : "",
        "ciphers"          : "HIGH:!aNULL:!MD5:!3DES:!CAMELLIA:!SRP:!PSK:@STRENGTH",
        "dry"              : "no",
        "type"             : "all",
        "keep"             : "",
        "trash"            : "no"
    }

    cafiles = [
        "/etc/ssl/certs/ca-certificates.crt",       # Debian, Ubuntu, Arch
        "/etc/pki/tls/certs/ca-bundle.crt",         # CentOS, Fedora
        "/etc/ssl/ca-bundle.pem",                   # OpenSUSE
        "/usr/local/share/certs/ca-root-nss.crt"    # FreeBSD
    ]

    for cafile in cafiles:
        if os.path.isfile(cafile):
            result["ca-file"] = cafile
            break

    return result


def pcl_load_config(filename, config = None):
    """
    Чтение секции [__title__] INI файла ~/.[__title__].cfg

    Аргументы:
        filename (str)  -- Имя INI файла
        config   (dict) -- Базовая конфигурация

    Результат (dict):
        Конфигурация приложения на основе файла конфигурации
    """
    if config == None:
        config = pcl_default_config()

    config = config.copy()

    parser = configparser.ConfigParser()
    parser.read(filename)

    for section in parser.sections():
        name = section.lower()
        if name == __title__:
            for option in parser.options(section):
                config[option.lower()] = parser.get(section, option).strip()

    return config


class pclOptions(object):
    """
    Опции приложения
    """
    def __init__(self, config):
        """
        Аргументы:
            config (dict) -- конфигурация приложения
        """
        self.timeout          = int(config["timeout"])
        self.retries          = int(config["retries"])
        self.delay            = int(config["delay"])
        self.chunk            = int(config["chunk"]) * 1024
        self.token            = str(config["token"])
        self.quiet            = self._bool(config["quiet"])
        self.debug            = self._bool(config["debug"]) and not self.quiet
        self.verbose          = (self._bool(config["verbose"]) or self.debug) and not self.quiet
        self.rsync            = self._bool(config["rsync"])
        self.recursion        = not self._bool(config["no-recursion"])
        self.no_recursion_tag = str(config["no-recursion-tag"])
        self.exclude_tag      = str(config["exclude-tag"])
        self.skip_hash        = self._bool(config["skip-hash"])
        self.progress         = self._bool(config["progress"]) and not self.quiet
        self.iconv            = str(config["iconv"])

        if self.iconv == "":
            self.iconv = None
        else:
            self.iconv = ["utf-8", self.iconv]

        self.baseurl   = str(config["base-url"])
        self.appid     = str(config["app-id"])
        self.appsecret = str(config["app-secret"])
        self.cafile    = str(config["ca-file"])
        self.ciphers   = str(config["ciphers"])

        if self.ciphers == "":
            self.ciphers = None

        if self.cafile == "":
            self.cafile = None

        self.dry   = self._bool(config["dry"])
        self.type  = str(config["type"])
        self.keep  = str(config["keep"])
        self.trash = self._bool(config["trash"])

        self.short = True if "short" in config else None
        self.long  = True if "long"  in config else None
        self.human = True if "human" in config or (self.short == None and self.long == None) else None

        if "PCLCMD_TOKEN" in os.environ:
            self.token = str(os.environ["PCLCMD_TOKEN"])
        if "SSL_CERT_FILE" in os.environ:
            self.cafile = str(os.environ["SSL_CERT_FILE"])


    def __repr__(self):
        return "{0!s}({1!r})".format(self.__class__, self.__dict__)


    @staticmethod
    def _bool(value):
        """
        Преобразование строкового значения к булевому

        Аргументы:
            value (str|bool) -- Строковое представление булева значения

        Результат (bool):
            Результат преобразования строкового значения к булеву - [true|yes|t|y|1] => True, иначе False
        """
        if type(value) is bool:
            return value

        value = value.lower().strip()

        if value == "true" or value == "yes" or value == "t" or value == "y" or value == "1":
            return True

        return False


class pclItem(object):
    """
    Описатель элемента в хранилище
    """
    def __init__(self, info = None):
        """
        Аргументы:
            info (dict) -- Описатель элемента
        """
        common_attr = ["name", "created", "modified", "path", "isfolder"]
        file_attr   = ["size", "hash"]

        for attr in common_attr:
            if attr not in info:
                raise ValueError("{0} not exists (incomplete response?)".format(attr))

        if info != None:
            for key, value in iteritems(info):
                self.__dict__[key] = value

        if self.isfolder == False:
            for attr in file_attr:
                if attr not in info:
                    raise ValueError("{0} not exists (incomplete response?)".format(attr))
            if "size" not in info:
                self.__dict__["size"] = 0
        elif self.isfolder == True:
            pass
        else:
            raise ValueError("Unknown item type: {0}".format(self.isfolder))


    @staticmethod
    def category_string(category):
        if category == 0:
            return "uncategorized"
        elif category == 1:
            return "image"
        elif category == 2:
            return "video"
        elif category == 3:
            return "audio"
        elif category == 4:
            return "document"
        elif category == 5:
            return "archive"

        return "unknown"


    def __str__(self):
        result = ""
        for key, value in iteritems(self.__dict__):
            if key == "created" or key == "modified":
                value = pcl_strftime(value)
            elif key == "category":
                value = "{0} ({1})".format(value, pclItem.category_string(value))
            result += "{0:>15}: {1}\n".format(key, value)

        return result


    def __repr__(self):
        return "{0!s}({1!r})".format(self.__class__, self.__dict__)


def pcl_check_python23(py2minor, py2micro, py3minor, py3micro):
    """
    Проверка версии Python для обеспечения совместимости

    Аргументы:
        py2minor (int) -- minor версия для 2.x
        py2micro (int) -- micro версия для 2.x
        py3minor (int) -- minor версия для 3.x
        py3micro (int) -- micro версия для 3.x

    Результат (bool):
        Соответствие версии >= аргументам
    """
    return sys.version_info >= (2, py2minor, py2micro) if sys.version_info < (3, 0) else sys.version_info >= (3, py3minor, py3micro)


def pcl_print(msg):
    """
    Вывод сообщения

    Аргументы:
        msg (str) -- Сообщение для вывода в stdout
    """
    sys.stdout.write("{0}\n".format(msg))


def pcl_verbose(errmsg, flag = True):
    """
    Вывод расширенной информации

    Аргументы:
        errmsg (str)  -- Сообщение для вывода в stderr
        flag   (bool) -- Флаг, разрешающий вывод сообщения
    """
    if flag:
        sys.stderr.write("{0}\n".format(errmsg))


def pcl_debug(errmsg, flag = True):
    """
    Вывод отладочной информации

    Аргументы:
        errmsg (str)  -- Сообщение для вывода в stderr
        flag   (bool) -- Флаг, разрешающий вывод сообщения
    """
    if flag:
        sys.stderr.write("--> {0}\n".format(errmsg))


def pcl_human(val):
    """
    Преобразование числа байт в человекочитаемый вид

    Аргументы:
        val (int) -- Значение в байтах

    Результат (str):
        Человекочитаемое значение с размерностью
    """
    if val < 1024:
        return "{0}".format(val)
    elif val < 1024 * 1024:
        return "{0:.0f}".format(val / 1024) + "K"
    elif val < 1024 * 1024 * 1024:
        return "{0:.0f}".format(val / 1024 / 1024) + "M"
    elif val < 1024 * 1024 * 1024 * 1024:
        return "{0:.2f}".format(val / 1024.0 / 1024.0 / 1024.0).rstrip("0").rstrip(".") + "G"

    return "{0:.2f}".format(val / 1024.0 / 1024.0 / 1024.0 / 1024.0).rstrip("0").rstrip(".") + "T"


def pcl_strftime(timestamp, format = "%Y-%m-%dT%H:%M:%S+00:00"):
    """
    Конвертация unixtime в строку требуемого формата

    Аргументы:
        timestamp (int) -- Unixtime
        format    (str) -- Формат даты

    Результат (str):
        Форматированная дата
    """
    return datetime.datetime.utcfromtimestamp(timestamp).strftime(format)


def pcl_remote_path(path):
    """
    Конвертация неявного пути в путь от корня в хранилище
    path/to, /path/to -> /path/to

    Аргументы:
        path (str) -- Путь

    Результат (str):
        Путь от корня в хранилище
    """
    if path[0] != "/":
        path = "/{0}".format(path)

    if path != "/" and path[-1] == "/":
        path = path[:-1]

    return path


def pcl_headers(token):
    """
    Получение HTTP заголовков по умолчанию

    Аргументы:
        token (str) -- OAuth токен

    Результат (dict):
        Заголовки по умолчанию для передачи в запросе к API
    """
    return {
        "Accept"        : "application/json",
        "User-Agent"    : "{0}/{1}".format(__title__, __version__),
        "Authorization" : "Bearer {0}".format(token)
    }


def pcl_query_download(options, response, filename):
    """
    Загрузка файла из хранилища

    Аргументы:
        options  (pclOptions)   -- Опции приложения
        response (HTTPResponse) -- HTTP ответ
        filename (str)          -- Имя локального файла для записи
    """
    if options.progress:
        read  = 0
        start = int(time.time())
        bar   = None

        try:
            total = int(response.info().get("Content-Length"))
            if pclProgressBar:
                try:
                    widgets = ["--> Download: ", pclProgressBar.Percentage(), " ", pclProgressBar.Bar(left = "[", marker = "=", right = "]"), " ", pclProgressBar.ETA(), " ", pclProgressBar.FileTransferSpeed()]
                    bar = pclProgressBar.ProgressBar(widgets = widgets, maxval = total).start()
                except:
                    total = pcl_human(total)
            else:
                total = pcl_human(total)
        except:
            total = "-"

    with open(filename, "wb") as fd:
        while True:
            part = response.read(options.chunk)
            if not part:
                break

            fd.write(part)

            if options.progress:
                read += len(part)
                if bar:
                    bar.update(read)
                else:
                    delta = int(time.time()) - start
                    if delta > 0:
                        sys.stderr.write("--> Download: {0}/{1} ({2}/s){3}\r".format(pcl_human(read), total, pcl_human(read / delta), " " * 12))

    if options.progress:
        if bar:
            bar.finish()
        else:
            sys.stderr.write("{0}\r".format(" " * 35))


def pcl_query_retry(options, method, url, args, headers = None, filename = None):
    """
    Реализация одной попытки запроса к API

    Аргументы:
        options  (pclOptions) -- Опции приложения
        method   (str)        -- Тип запроса (GET|POST|PUT|DELETE)
        url      (str)        -- URL запроса
        args     (dict)       -- Параметры запроса
        headers  (dict)       -- Заголовки запроса
        filename (str)        -- Имя файла для отправки / получения

    Результат (dict):
        Результат вызова API, преобразованный из JSON

    Исключения:
        pclError     -- При возврате HTTP кода отличного от HTTP-200 (errno будет равен HTTP коду)
        pclCertError -- При ошибке проверки сертификата сервера
    """
    if headers == None:
        headers = pcl_headers(options.token)

    url += ("" if args == None else "?{0}".format(pcl_urlencode(args)))

    if options.debug:
        pcl_debug("{0} {1}".format(method, url))
        if filename != None:
            pcl_debug("File: {0}".format(filename))

    # страховка
    if re.match('^https:\/\/[a-z0-9\.\-]+\.pcloud\.com(:443){,1}\/', url, re.IGNORECASE) == None:
        raise RuntimeError("Malformed URL {0}".format(url))

    if method not in ["GET", "POST"]:
        raise ValueError("Unknown method: {0}".format(method))

    fd = None
    if method == "POST" and filename != None:
        fd = open(filename, "rb")

    request = pclRequest(url, fd, headers)
    request.get_method = lambda: method

    try:
        opener = pcl_build_opener(pclHTTPSHandler(options))
        result = opener.open(request, timeout = options.timeout)
        code   = result.getcode()

        if code == 204 or code == 201:
            return {}
        elif method == "GET" and filename != None:
            pcl_query_download(options, result, filename)
            return {}
        else:
            def _json_convert(input):
                """
                Конвертер unicode строк в utf-8 при вызове json.load
                """
                if isinstance(input, dict):
                    return dict([(_json_convert(key), _json_convert(value)) for key, value in iteritems(input)])
                elif isinstance(input, list):
                    return [_json_convert(element) for element in input]
                elif isinstance(input, unicode):
                    return input.encode("utf-8")
                else:
                    return input

            if sys.version_info < (3, 0):
                result = json.load(result, object_hook = _json_convert)
            else:
                result = json.load(codecs.getreader("utf-8")(result))

            # https://docs.pcloud.com/http_json_protocol/index.html
            if not "result" in result:
                raise pclError(500, "Invalid response (result field not found)")

            if result["result"] != 0:
                if not "error" in result:
                    result["error"] = "Unknown error"
                raise pclError(result["result"], result["error"])

            return result

    except pclHTTPError as e:
        errmsg = "HTTP-{0}: {1}".format(e.code, e.msg)
        raise pclError(e.code, errmsg)


def pcl_can_query_retry(e):
    """
    Проверка исключения при вызове pcl_query_retry на возможность повторного запроса

    Аргументы:
        e (Exception) -- Исключение из pcl_query_retry

    Результат:
        None или необработанное исключение
    """
    if type(e) == pclError:
        # https://docs.pcloud.com/errors/index.html
        if e.errno >= 3000:
            pass
        # HTTP
        elif (e.errno >= 500 and e.errno < 600) or e.errno == 401 or e.errno == 429:
            pass
        else:
            raise e
    elif type(e) == socket.error and not (e.errno == errno.ECONNRESET or e.errno == errno.ECONNREFUSED):
        raise e


def pcl_query(options, method, url, args, headers = None, filename = None):
    """
    Реализация нескольких попыток запроса к API (pcl_query_retry)
    """
    retry = 0
    while True:
        try:
            return pcl_query_retry(options, method, url, args, headers, filename)
        except (pclURLError, pclBadStatusLine, pclCannotSendRequest, ssl.SSLError, socket.error, pclError) as e:
            pcl_can_query_retry(e)
            retry += 1
            pcl_debug("Retry {0}/{1}: {2}".format(retry, options.retries, e), options.debug)
            if retry >= options.retries:
                raise pclError(1, e)
            time.sleep(options.delay)


def pcl_info(options):
    """
    Получение метаинформации о хранилище

    Аргументы:
        options (pclOptions) -- Опции приложения

    Результат (dict):
        Метаинформация о хранилище
    """
    method = "GET"
    url    = options.baseurl + "/userinfo"

    return pcl_query(options, method, url, None)


def pcl_hash(options, path, silent = False):
    """
    Получение хэша файла

    Аргументы:
        options (pclOptions) -- Опции приложения
        path    (str)        -- Имя файла в хранилище
        silent  (bool)       -- Игнорировать ошибку, если файл (уже/еще?) не существует

    Результат (pclItem, sha1, md5):
        Метаинформация о запрашиваемом файле и хэши
    """
    pcl_verbose("Get Hash: {0}".format(path), options.verbose)

    args = {
        "path" : path
    }

    method = "GET"
    url    = options.baseurl + "/checksumfile"

    try:
        part = pcl_query(options, method, url, args)
    except pclError as e:
        # 2009 - file not found
        if not (silent and e.errno == 2009):
            raise e
        else:
            return (None, None, None)

    if not "metadata" in part:
        raise pclError(404, "metadata not found in response")
    if not "sha1" in part:
        raise pclError(404, "sha1 not found in response")
    if not "md5" in part:
        raise pclError(404, "md5 not found in response")

    # в мета-информации отстутствует путь к файлу
    if not "path" in part["metadata"]:
        part["metadata"]["path"] = path

    return (pclItem(part["metadata"]), part["sha1"], part["md5"])


def pcl_stat(options, path):
    """
    Получение метаинформации об объекте в хранилище

    Поскольку в рамках одного пути может присутствовать
    файл и директория с одинаковыми именами, результат
    разделен на два элемента

    Аргументы:
        options (pclOptions) -- Опции приложения
        path    (str)        -- Имя файла или директории в хранилище

    Результат (pclItem, pclItem):
        Метаинформация о запрашиваемой директории
        Метаинформация о запрашиваемом файле
    """
    meta, dirs, files = pcl_list(options, os.path.dirname(path))

    if path == "/":
        return (meta, None)

    path  = os.path.basename(path)
    dirs  = dirs[path]  if path in dirs  else None
    files = files[path] if path in files else None

    return (dirs, files)


def pcl_list(options, path, silent = False):
    """
    Получение списка файлов и директорий в хранилище

    Поскольку в рамках одного пути может присутствовать
    файл и директория с одинаковыми именами, результат
    разделен на два словаря

    Аргументы:
        options (pclOptions) -- Опции приложения
        path    (str)        -- Путь в хранилище
        silent  (bool)       -- Игноририровать ошибку, если директория (уже/еще?) не существует

    Результат (pclItem, dict, dict):
        Метаинформация о запрашиваемой директории
        Список директорий { "имя" : pclItem }
        Список файлов { "имя" : pclItem }
    """
    args = {
        "path"       : path,
        "timeformat" : "timestamp"
    }

    method = "GET"
    url    = options.baseurl + "/listfolder"

    try:
        part = pcl_query(options, method, url, args)
    except pclError as e:
        # 2005 - directory does not exist
        if not (silent and e.errno == 2005):
            raise e
        else:
            return (None, {}, {})

    if not "metadata" in part:
        raise pclError(404, "metadata not found in response")

    dirs  = {}
    files = {}

    if "contents" in part["metadata"]:
        for item in part["metadata"]["contents"]:
            item = pclItem(item)
            if item.isfolder:
                dirs[item.name] = item
            else:
                files[item.name] = item

        del part["metadata"]["contents"]

    meta = pclItem(part["metadata"])

    return (meta, dirs, files)


def pcl_mkdir(options, path, silent = False):
    """
    Cоздание директории в хранилище

    Аргументы:
        options (pclOptions) -- Опции приложения
        path    (str)        -- Имя директории в хранилище
        silent  (bool)       -- Игноририровать ошибку, если директория (уже/еще?) существует

    Результат (bool):
        True, если директория была создана, иначе (для silent = True) False
    """
    pcl_verbose("Create dir: {0}".format(path), options.verbose)

    args = {
        "path" : path
    }

    method = "GET"
    url    = options.baseurl + "/createfolder"

    try:
        pcl_query(options, method, url, args)
    except pclError as e:
        # 2004 - file or folder alredy exists
        if not (silent and e.errno == 2004):
            raise e
        else:
            return False

    return True


def pcl_rm_dir(options, path, silent = False):
    """
    Удаление директории в хранилище

    Аргументы:
        options (pclOptions) -- Опции приложения
        path    (str)        -- Объект хранилища
        silent  (bool)       -- Игнорировать ошибку, если директория (уже/еще?) не существует

    Результат (bool):
        True, если директория была удалена, иначе (для silent = True) False
    """
    pcl_verbose("Delete dir: {0}".format(path), options.verbose)

    args = {
        "path" : path
    }

    method = "GET"
    url    = options.baseurl + "/deletefolderrecursive"

    try:
        pcl_query(options, method, url, args)
    except pclError as e:
        # 2005 - directory does not exist
        if not (silent and e.errno == 2005):
            raise e
        else:
            return False

    return True


def pcl_rm_file(options, path, silent = False):
    """
    Удаление файла в хранилище

    Аргументы:
        options (pclOptions) -- Опции приложения
        path    (str)        -- Объект хранилища
        silent  (bool)       -- Игнорировать ошибку, если файл (уже/еще?) не существует

    Результат (bool):
        True, если файл был удален, иначе (для silent = True) False
    """
    pcl_verbose("Delete file: {0}".format(path), options.verbose)

    args = {
        "path" : path
    }

    method = "GET"
    url    = options.baseurl + "/deletefile"

    try:
        pcl_query(options, method, url, args)
    except pclError as e:
        # 2009 - file not found
        if not (silent and e.errno == 2009):
            raise e
        else:
            return False

    return True


def pcl_trash_clear(options, id, isfolder):
    """
    Удаление директории или файла из корзины

    Аргументы:
        options  (pclOptions) -- Опции приложения
        id       (int)        -- ID элемента
        isfolder (bool)       -- Флаг удаления директории
    """
    args = {}

    if isfolder:
        args["folderid"] = id
    else:
        args["fileid"] = id

    method = "GET"
    url    = options.baseurl + "/trash_clear"

    pcl_query(options, method, url, args)


def pcl_rm(options, item):
    """
    Удаление элемента

    Аргументы:
        options (pclOptions) -- Опции приложения
        item    (pclItem)    -- Описатель элемента
    """
    if item.isfolder:
        pcl_rm_dir(options, item.path)
    else:
        pcl_rm_file(options, item.path)

    if not options.trash:
        if item.isfolder:
            pcl_trash_clear(options, item.folderid, True)
        else:
            pcl_trash_clear(options, item.fileid, False)


def pcl_mv_dir(options, source, target):
    """
    Перемещение директории в хранилище

    Аргументы:
        options (pclOptions) -- Опции приложения
        source  (str)        -- Исходная директория хранилища
        target  (str)        -- Конечная директория хранилища
    """
    pcl_verbose("Move dir: {0} -> {1}".format(source, target), options.verbose)

    args = {
        "path"   : source,
        "topath" : target
    }

    method = "GET"
    url    = options.baseurl + "/renamefolder"

    pcl_query(options, method, url, args)


def pcl_mv_file(options, source, target):
    """
    Перемещение файла в хранилище

    Аргументы:
        options (pclOptions) -- Опции приложения
        source  (str)        -- Исходный файл хранилища
        target  (str)        -- Конечный файл хранилища
    """
    pcl_verbose("Move file: {0} -> {1}".format(source, target), options.verbose)

    args = {
        "path"   : source,
        "topath" : target
    }

    method = "GET"
    url    = options.baseurl + "/renamefile"

    pcl_query(options, method, url, args)


def pcl_mv(options, source, target):
    """
    Перемещение объекта в хранилище

    Аргументы:
        options (pclOptions) -- Опции приложения
        source  (pclItem)    -- Исходный объект хранилища
        target  (str)        -- Конечный объект хранилища
    """
    if source.isfolder:
        pcl_mv_dir(options, source.path, target)
    else:
        pcl_mv_file(options, source.path, target)


def pcl_cp_dir(options, source, target):
    """
    Копирование директории в хранилище

    Аргументы:
        options (pclOptions) -- Опции приложения
        source  (str)        -- Исходная директория хранилища
        target  (str)        -- Конечная директория хранилища
    """
    pcl_verbose("Copy dir: {0} -> {1}".format(source, target), options.verbose)

    raise pclError(501, "Not implemented")


def pcl_cp_file(options, source, target):
    """
    Копирование файла в хранилище

    Аргументы:
        options (pclOptions) -- Опции приложения
        source  (str)        -- Исходный файл хранилища
        target  (str)        -- Конечный файл хранилища
    """
    pcl_verbose("Copy file: {0} -> {1}".format(source, target), options.verbose)

    args = {
        "path"   : source,
        "topath" : target
    }

    method = "GET"
    url    = options.baseurl + "/copyfile"

    pcl_query(options, method, url, args)


def pcl_cp(options, source, target):
    """
    Копирование объекта в хранилище

    Аргументы:
        options (pclOptions) -- Опции приложения
        source  (pclItem)    -- Исходный объект хранилища
        target  (str)        -- Конечный объект хранилища
    """
    if source.isfolder:
        pcl_cp_dir(options, source.path, target)
    else:
        pcl_cp_file(options, source.path, target)


def pcl_publish_dir(options, path):
    """
    Публикация директории (директория становится доступна по прямой ссылке)

    Аргументы:
        options (pclOptions) -- Опции приложения
        path    (str)        -- Директория хранилища
    """
    pcl_verbose("Publish dir: {0}".format(path), options.verbose)

    args = {
        "path" : path
    }

    method = "GET"
    url    = options.baseurl + "/getfolderpublink"

    result = pcl_query(options, method, url, args)

    return result["link"]


def pcl_publish_file(options, path):
    """
    Публикация файла (файл становится доступен по прямой ссылке)

    Аргументы:
        options (pclOptions) -- Опции приложения
        path    (str)        -- Файл хранилища
    """
    pcl_verbose("Publish file: {0}".format(path), options.verbose)

    args = {
        "path" : path
    }

    method = "GET"
    url    = options.baseurl + "/getfilepublink"

    result = pcl_query(options, method, url, args)

    return result["link"]


def pcl_publish(options, item):
    """
    Публикация объекта (объект становится доступен по прямой ссылке)

    Аргументы:
        options (pclOptions) -- Опции приложения
        item    (pclItem)    -- Объект хранилища

    Результат (str):
        Ссылка для скачивания
    """
    if item.isfolder:
        link = pcl_publish_dir(options, item.path)
    else:
        link = pcl_publish_file(options, item.path)

    return link


def pcl_list_publinks(options):
    """
    Получение списка публичных ссылок

    Аргументы:
        options (pclOptions) -- Опции приложения
    """
    method = "GET"
    url    = options.baseurl + "/listpublinks"

    result = pcl_query(options, method, url, None)

    raise pclError(501, "Not implemented")


def pcl_unpublish(options, path):
    """
    Закрытие публичного доступа к объекту (объект становится недоступен по прямой ссылке)

    Аргументы:
        options (pclOptions) -- Опции приложения
        path    (str)        -- Имя файла или директории в хранилище
    """
    raise pclError(501, "Not implemented")


def pcl_download(options, source, target):
    """
    Скачивание файла из интернета в хранилище

    Аргументы:
        options (pclOptions) -- Опции приложения
        source  (str)        -- URL исходного объекта
        target  (str)        -- Конечный объект хранилища
    """
    pcl_verbose("Download: {0} -> {1}".format(source, target), options.verbose)

    if os.path.basename(target) != "":
        args = {
            "url"    : source,
            "path"   : os.path.dirname(target),
            "target" : os.path.basename(target)
        }
    else:
        args = {
            "url"  : source,
            "path" : target
        }

    method = "GET"
    url    = options.baseurl + "/downloadfile"

    result = pcl_query(options, method, url, args)


def pcl_calc_hash(options, filename):
    """
    Подсчет sha1/md5 хэша файла

    Аргументы:
        options  (pclOptions) -- Опции приложения
        filename (str)        -- Имя файла

    Результат (sha1, md5):
        Хэши файла
    """
    pcl_debug("SHA1/MD5: " + filename, options.debug)

    with open(filename, "rb") as fd:
        hasher_sha1 = hashlib.sha1()
        hasher_md5  = hashlib.md5()
        while True:
            data = fd.read(options.chunk)
            if not data:
                break
            hasher_sha1.update(data)
            hasher_md5.update(data)

        return (hasher_sha1.hexdigest(), hasher_md5.hexdigest())


def pcl_check_hash(options, filename, sha1, md5):
    """
    Проверка хэшей файла

    Аргументы:
        options  (pclOptions) -- Опции приложения
        filename (str)        -- Имя файла
        sha1     (str)        -- Сравниваемное значение SHA1
        md5      (str)        -- Сравниваемное значение MD5

    Результат (bool):
        Результат сравнения хэшей
    """
    if options.skip_hash:
        return True

    fsha1, fmd5 = pcl_calc_hash(options, filename)
    if fsha1 == sha1 and fmd5 == md5:
        return True

    return False


def pcl_put_retry(options, source, target):
    """
    Реализация одной попытки помещения файла в хранилище

    Аргументы:
        options (pclOptions) -- Опции приложения
        source  (str)        -- Имя локального файла
        target  (str)        -- Имя файла в хранилище
    """
    args = {
        "path"      : os.path.dirname(target),
        "nopartial" : 1,
        "filename"  : os.path.basename(target)
    }

    method = "POST"
    url    = options.baseurl + "/uploadfile"

    headers = pcl_headers(options.token)
    headers["Content-Type"]   = "application/octet-stream"
    headers["Content-Length"] = os.path.getsize(source)

    pcl_query_retry(options, method, url, args, headers, source)


def pcl_put(options, source, target):
    """
    Реализация нескольких попыток загрузки файла в хранилище (pcl_put_retry)
    """
    pcl_verbose("Transfer: {0} ({1}) -> {2}".format(source, pcl_human(os.path.getsize(source)), target), options.verbose)

    retry = 0
    while True:
        try:
            pcl_put_retry(options, source, target)
            break
        except (pclURLError, pclBadStatusLine, pclCannotSendRequest, ssl.SSLError, socket.error, pclError) as e:
            pcl_can_query_retry(e)
            retry += 1
            pcl_debug("Retry {0}/{1}: {2}".format(retry, options.retries, e), options.debug)
            if retry >= options.retries:
                raise pclError(1, e)
            time.sleep(options.delay)


def pcl_iconv(options, name):
    """
    Попытка преобразования имени файла или директории из кодировки отличной от utf-8

    Аргументы:
        options (pclOptions) -- Опции приложения
        source  (str)        -- Имя локальной директории
    """
    if not options.iconv:
        return name

    for encoding in options.iconv:
        try:
            return name.decode(encoding).encode("utf-8")
        except UnicodeDecodeError:
            pass

    return None


def pcl_put_sync(options, source, target):
    """
    Синхронизация локальных файлов и директорий с находящимися в хранилище

    Аргументы:
        options (pclOptions) -- Опции приложения
        source  (str)        -- Имя локальной директории (со слешем)
        target  (str)        -- Имя директории в хранилище (со слешем)
    """
    if options.exclude_tag and os.path.isfile(source + options.exclude_tag):
        return

    local_recursion = True
    if options.no_recursion_tag and os.path.isfile(source + options.no_recursion_tag):
        local_recursion = False

    meta, dlist, flist = pcl_list(options, pcl_remote_path(target), True)
    if not meta:
        pcl_mkdir(options, pcl_remote_path(target))

    lazy_put_sync = []

    for item in os.listdir(source):
        sitem = source + item

        item = pcl_iconv(options, item)
        if not item:
            pcl_verbose("Skip: {0}".format(sitem), options.verbose)
            continue

        titem = target + item

        if not os.path.islink(sitem):
            if os.path.isdir(sitem):
                if options.recursion and local_recursion:
                    lazy_put_sync.append([sitem + "/", titem + "/"])
                if item not in dlist:
                    pcl_mkdir(options, titem)
                else:
                    del dlist[item]
            elif os.path.isfile(sitem):
                meta = None
                if not options.skip_hash:
                    meta, sha1, md5 = pcl_hash(options, titem, True)
                if not (meta and os.path.getsize(sitem) == meta.size and pcl_check_hash(options, sitem, sha1, md5)):
                    # при удалении в корзину и последующем создании файла с тем же путем он будет восстановлен из корзины и добавлена новая ревизия
                    # при таком неочивидном поведении теряется смысл в попытке его удаления
                    if meta and not options.trash:
                        pcl_rm(options, meta)
                    pcl_put(options, sitem, titem)
                if item in flist:
                    del flist[item]
            else:
                raise pclError(1, "Unsupported filesystem object: {0}".format(sitem))
        else:
            pcl_verbose("Skip: {0}".format(sitem), options.verbose)

    if options.rsync:
        for item in itervalues(dlist):
            pcl_rm(options, item)
        for item in itervalues(flist):
            pcl_rm(options, item)

    # при большом количестве директорий рандомизация позволяет продолжить
    # загрузку не обрабатывая заново ранее загруженные директории
    random.shuffle(lazy_put_sync)

    index = 0
    count = len(lazy_put_sync)

    for [sitem, titem] in lazy_put_sync:
        try:
            index += 1
            pcl_verbose("Processing [{0}/{1}]: {2}".format(index, count, sitem), options.verbose)
            pcl_put_sync(options, sitem, titem)
        except OSError as e:
            # аналогично поведению rsync, которая не останавливается с ошибкой
            # при исчезновении файлов и директорий во время синхронизации
            if e.errno == errno.ENOENT:
                pcl_verbose("Warning: {0}".format(e), options.verbose)
            else:
                raise e


def pcl_get_retry(options, source, target):
    """
    Реализация одной попытки получения файла из хранилища

    Аргументы:
        options (pclOptions) -- Опции приложения
        source  (str)        -- Имя файла в хранилище
        target  (str)        -- Имя локального файла
    """
    args = {
        "path" : source
    }

    method = "GET"
    url    = options.baseurl + "/getfilelink"

    result = pcl_query_retry(options, method, url, args)

    if "path" in result and "hosts" in result and isinstance(result["hosts"], list) and len(result["hosts"]) > 0:
        url = "https://{0}{1}".format(result["hosts"][0], result["path"])

        headers = pcl_headers(options.token)
        headers["Accept"] = "*/*"

        del headers["Authorization"]

        pcl_query_retry(options, method, url, None, headers, target)
    else:
        raise RuntimeError("Incomplete response")


def pcl_get(options, source, target):
    """
    Реализация нескольких попыток получения файла из хранилища (pcl_get_retry)
    """
    pcl_verbose("Transfer: {0} -> {1}".format(source, target), options.verbose)

    retry = 0
    while True:
        try:
            pcl_get_retry(options, source, target)
            break
        except (pclURLError, pclBadStatusLine, pclCannotSendRequest, ssl.SSLError, socket.error, pclError) as e:
            pcl_can_query_retry(e)
            retry += 1
            pcl_debug("Retry {0}/{1}: {2}".format(retry, options.retries, e), options.debug)
            if retry >= options.retries:
                raise pclError(1, e)
            time.sleep(options.delay)


def pcl_ensure_local(options, path, type):
    """
    Метод проверки возможности создания локального объекта требуемого типа.
    Если объект уже существует и типы не совпадают, производится удаление объекта.
    Если требуемый тип является директорией, то в случае ее отсутствия производится ее создание.

    Аргументы:
        options (pclOptions) -- Опции приложения
        path    (str)        -- Объект
        type    (str)        -- Тип объекта (file|dir)

    Результат (bool):
        True если объект нужного типа уже существует, иначе False
    """
    if not (type == "dir" or type == "file"):
        raise ValueError("Unsupported type: {0}".format(type))

    if os.path.exists(path):
        if os.path.islink(path):
            pcl_debug("rm {0}".format(path), options.debug)
            os.unlink(path)
            return False
        if type == "dir":
            if os.path.isdir(path):
                return True
            elif os.path.isfile(path):
                pcl_debug("rm {0}".format(path), options.debug)
                os.remove(path)
            else:
                raise pclError(1, "Unsupported filesystem object: {0}".format(path))
        elif type == "file":
            if os.path.isfile(path):
                return True
            elif os.path.isdir(path):
                pcl_debug("rm -r {0}".format(path), options.debug)
                shutil.rmtree(path)
            else:
                raise pclError(1, "Unsupported filesystem object: {0}".format(path))
    elif type == "dir":
        pcl_debug("mkdir {0}".format(path), options.debug)
        os.mkdir(path)
        return True

    return False


def pcl_get_sync(options, source, target):
    """
    Синхронизация файлов и директорий в хранилище с локальными

    Аргументы:
        options (pclOptions) -- Опции приложения
        source  (str)        -- Имя директории в хранилище (со слешем)
        target  (str)        -- Имя локальной директории (со слешем)
    """
    meta, dlist, flist = pcl_list(options, pcl_remote_path(source))

    if len(dlist) > len(flist):
        for item in itervalues(flist):
            if item.name in dlist:
                raise pclError(409, "Undefined behaviour - file AND directory with same name exists")
    else:
        for item in itervalues(dlist):
            if item.name in flist:
                raise pclError(409, "Undefined behaviour - file AND directory with same name exists")

    lazy_get_sync = []

    for item in itervalues(dlist):
        sitem = source + item.name
        titem = target + item.name

        if options.recursion:
            lazy_get_sync.append([sitem + "/", titem + "/"])

        pcl_ensure_local(options, titem, "dir")

    for item in itervalues(flist):
        sitem = source + item.name
        titem = target + item.name

        exists = pcl_ensure_local(options, titem, "file")

        meta = None
        if exists and not options.skip_hash:
            meta, sha1, md5 = pcl_hash(options, sitem)

        if not exists or not (os.path.getsize(titem) == item.size and pcl_check_hash(options, titem, sha1, md5)):
            pcl_get(options, sitem, titem)

    if options.rsync:
        for item in os.listdir(target):
            if item not in dlist and item not in flist:
                titem = target + item
                if os.path.islink(titem):
                    pcl_debug("rm {0}".format(titem), options.debug)
                    os.remove(titem)
                elif os.path.isfile(titem):
                    pcl_debug("rm {0}".format(titem), options.debug)
                    os.remove(titem)
                elif os.path.isdir(titem):
                    pcl_debug("rm -r {0}".format(titem), options.debug)
                    shutil.rmtree(titem)
                else:
                    raise pclError(1, "Unsupported filesystem object: {0}".format(titem))

    # при большом количестве директорий рандомизация позволяет продолжить
    # загрузку не обрабатывая заново ранее загруженные директории
    random.shuffle(lazy_get_sync)

    index = 0
    count = len(lazy_get_sync)

    for [sitem, titem] in lazy_get_sync:
        try:
            index += 1
            pcl_verbose("Processing [{0}/{1}]: {2}".format(index, count, sitem), options.verbose)
            pcl_get_sync(options, sitem, titem)
        except pclError as e:
            # аналогично поведению rsync, которая не останавливается с ошибкой
            # при исчезновении файлов и директорий во время синхронизации
            if e.errno == 404:
                pcl_verbose("Warning: {0}".format(e), options.verbose)
            else:
                raise e


def pcl_clean(options, path):
    """
    Очистка файлов и директорий

    Аргументы:
        options (pclOptions) -- Опции приложения
        path    (str)        -- Путь
    """
    if options.keep == "" or options.type not in ["all", "file", "dir"]:
        return

    meta, dlist, flist = pcl_list(options, path)

    ilist = []

    if options.type == "all" or options.type == "dir":
        for item in itervalues(dlist):
            ilist.append(item)

    if options.type == "all" or options.type == "file":
        for item in itervalues(flist):
            ilist.append(item)

    for item in ilist:
        item.modified = datetime.datetime.fromtimestamp(item.modified, dateutil.tz.tzutc())

    ilist.sort(key = lambda x: x.modified)

    if re.match("^[0-9]+$", options.keep, re.IGNORECASE) != None:
        pcl_verbose("Clean: <{0}> keep last {1}".format(options.type, options.keep), options.verbose)
        ilist = ilist[:-int(options.keep)]
    elif re.match("^[0-9]+[dwmy]$", options.keep, re.IGNORECASE):
        m = re.split("^([0-9]+)([dwmy])$", options.keep, re.IGNORECASE)
        if m != None and len(m) == 4:
            count    = int(m[1])
            interval = str(m[2])

            relative = None
            if interval == "d":
                relative = dateutil.relativedelta.relativedelta(days = -count)
            elif interval == "w":
                relative = dateutil.relativedelta.relativedelta(weeks = -count)
            elif interval == "m":
                relative = dateutil.relativedelta.relativedelta(months = -count)
            elif interval == "y":
                relative = dateutil.relativedelta.relativedelta(years = -count)

            relative = datetime.datetime.now(dateutil.tz.tzutc()).replace(microsecond = 0) + relative

            pcl_verbose("Clean: <{0}> before {1}".format(options.type, relative.isoformat()), options.verbose)

            tlist = []
            for item in ilist:
                if item.modified < relative:
                    tlist.append(item)

            ilist = tlist
    elif len(options.keep) >= 10:   # YYYY-MM-DD
        relative = dateutil.parser.parse(options.keep).astimezone(dateutil.tz.tzutc())

        pcl_verbose("Clean: <{0}> before {1}".format(options.type, relative.isoformat()), options.verbose)

        tlist = []
        for item in ilist:
            if item.modified < relative:
                tlist.append(item)

        ilist = tlist
    else:
        return

    for item in ilist:
        if options.dry:
            pcl_print("{0:>25}  {1:>7}  {2}".format(item.modified.isoformat(), "<{0}>".format("dir" if item.isfolder else "file"), item.name))
        else:
            pcl_rm(options, item)


def pcl_token_cmd(options, args):
    """
    Получение OAuth токена для приложения

    Аргументы:
        options (pclOptions) -- Опции приложения
        args    (dict)       -- Аргументы командной строки
    """
    if len(args) > 1:
        raise pclError(1, "Too many arguments")

    if len(args) == 0:
        pcl_print("Open URL below in your browser, allow access and paste code as argument")
        pcl_print("https://my.pcloud.com/oauth2/authorize?response_type=code&client_id={0}".format(options.appid))
        return

    args = {
        "client_id"     : options.appid,
        "client_secret" : options.appsecret,
        "code"          : args[0]
    }

    method  = "GET"
    url     = options.baseurl + "/oauth2_token"
    headers = pcl_headers(options.token)

    del headers["Authorization"]

    result = pcl_query_retry(options, method, url, args, headers)

    pcl_print("OAuth token is: {0}".format(result["access_token"]))


def pcl_info_cmd(options, args):
    """
    Вывод метаинформации о хранилище

    Аргументы:
        options (pclOptions) -- Опции приложения
        args    (dict)       -- Аргументы командной строки
    """
    if len(args) > 0:
        raise pclError(1, "Too many arguments")

    result = pcl_info(options)

    result["freequota"]     = int(result["quota"]) - int(result["usedquota"])
    result["usedquota_pct"] = int(result["usedquota"]) * 100 / int(result["quota"])

    if result["freequota"] < 0:
        result["freequota"] = 0
    if result["usedquota_pct"] > 100:
        result["usedquota_pct"] = 100

    if options.human:
        result["usedquota"] = pcl_human(result["usedquota"])
        result["freequota"] = pcl_human(result["freequota"])
        result["quota"]     = pcl_human(result["quota"])

    pcl_print("{0:>7}: {1} ({2:.0f}%)".format("Used", result["usedquota"], result["usedquota_pct"]))
    pcl_print("{0:>7}: {1}".format("Free", result["freequota"]))
    pcl_print("{0:>7}: {1}".format("Total", result["quota"]))


def pcl_stat_cmd(options, args):
    """
    Вывод метаинформации об объекте в хранилище

    Аргументы:
        options (pclOptions) -- Опции приложения
        args    (dict)       -- Аргументы командной строки
    """
    if len(args) > 1:
        raise pclError(1, "Too many arguments")

    path = "/"
    if len(args) > 0:
        path = args[0]

    ditem, fitem = pcl_stat(options, pcl_remote_path(path))

    if ditem:
        pcl_print(ditem)

    if fitem:
        pcl_print(fitem)


def pcl_ls_cmd(options, args):
    """
    Вывод списка файлов и директорий в хранилище

    Аргументы:
        options (pclOptions) -- Опции приложения
        args    (dict)       -- Аргументы командной строки
    """
    if len(args) > 1:
        raise pclError(1, "Too many arguments")

    path = "/"
    if len(args) > 0:
        path = args[0]

    meta, dirs, files = pcl_list(options, pcl_remote_path(path))

    dirs = listvalues(dirs)
    dirs.sort(key = lambda x: x.name)

    files = listvalues(files)
    files.sort(key = lambda x: x.name)

    for item in dirs:
        if options.long:
            pcl_print("{0}  {1:>25}  {2:>11}  {3}".format(pcl_strftime(item.created), pcl_strftime(item.modified), "<dir>", item.name))
        elif options.short:
            pcl_print("{0}".format(item.name))
        else:
            pcl_print("{0:>7}  {1}".format("<dir>", item.name))

    for item in files:
        if options.human:
            size = pcl_human(item.size)
        else:
            size = item.size

        if options.long:
            pcl_print("{0}  {1:>25}  {2:>11}  {3}".format(pcl_strftime(item.created), pcl_strftime(item.modified), size, item.name))
        elif options.short:
            pcl_print("{0}".format(item.name))
        else:
            pcl_print("{0:>7}  {1}".format(size, item.name))


def pcl_mkdir_cmd(options, args):
    """
    Обработчик создания директории в хранилище

    Аргументы:
        options (pclOptions) -- Опции приложения
        args    (dict)       -- Аргументы командной строки
    """
    if len(args) < 1:
        raise pclError(1, "Directory name not specified")

    for arg in args:
        pcl_mkdir(options, pcl_remote_path(arg))


def pcl_rm_cmd(options, args):
    """
    Обработчик удаления объекта хранилище

    Аргументы:
        options (pclOptions) -- Опции приложения
        args    (dict)       -- Аргументы командной строки
    """
    if len(args) < 1:
        raise pclError(1, "File or directory not specified")

    ditem, fitem = pcl_stat(options, pcl_remote_path(args[0]))

    if ditem:
        pcl_rm(options, ditem)
    if fitem:
        pcl_rm(options, fitem)


def pcl_mv_cmd(options, args):
    """
    Обработчик перемещения объекта в хранилище

    Аргументы:
        options (pclOptions) -- Опции приложения
        args    (dict)       -- Аргументы командной строки
    """
    if len(args) < 2:
        raise pclError(1, "Source or target not specified")
    if len(args) > 2:
        raise pclError(1, "Too many arguments")

    source = pcl_remote_path(args[0])
    target = pcl_remote_path(args[1])

    ditem, fitem = pcl_stat(options, source)

    if ditem:
        pcl_mv(options, ditem, target)
    if fitem:
        pcl_mv(options, fitem, target)


def pcl_cp_cmd(options, args):
    """
    Обработчик копирования объекта в хранилище

    Аргументы:
        options (pclOptions) -- Опции приложения
        args    (dict)       -- Аргументы командной строки
    """
    if len(args) < 2:
        raise pclError(1, "Source or target not specified")
    if len(args) > 2:
        raise pclError(1, "Too many arguments")

    source = pcl_remote_path(args[0])
    target = pcl_remote_path(args[1])

    ditem, fitem = pcl_stat(options, source)

    if ditem:
        pcl_cp(options, ditem, target)
    if fitem:
        pcl_cp(options, fitem, target)


def pcl_share_cmd(options, args):
    """
    Обработчик публикации объекта (объект становится доступен по прямой ссылке)

    Аргументы:
        options (pclOptions) -- Опции приложения
        args    (dict)       -- Аргументы командной строки
    """
    if len(args) < 1:
        raise pclError(1, "Object name not specified")

    for arg in args:
        ditem, fitem = pcl_stat(options, pcl_remote_path(arg))
        if ditem:
            link = pcl_publish(options, ditem)
            pcl_print("{0} -> {1}".format(ditem.path, link))
        if fitem:
            link = pcl_publish(options, fitem)
            pcl_print("{0} -> {1}".format(fitem.path, link))


def pcl_revoke_cmd(options, args):
    """
    Обработчик закрытия публичного доступа к объекту (объект становится недоступен по прямой ссылке)

    Аргументы:
        options (pclOptions) -- Опции приложения
        args    (dict)       -- Аргументы командной строки
    """
    if len(args) < 1:
        raise pclError(1, "Object name not specified")

    for arg in args:
        pcl_unpublish(options, pcl_remote_path(arg))


def pcl_put_cmd(options, args):
    """
    Обработчик загрузки файла в хранилище

    Аргументы:
        options (pclOptions) -- Опции приложения
        args    (dict)       -- Аргументы командной строки
    """
    if len(args) < 1:
        raise pclError(1, "Source not specified")
    if len(args) > 2:
        raise pclError(1, "Too many arguments")

    source = args[0]

    if len(args) == 2:
        target = args[1]
    else:
        target = "/"

    if os.path.basename(target) == "":
        target += os.path.basename(source)

    if not os.path.islink(source):
        if os.path.isdir(source):
            if os.path.basename(source) != "":
                source += "/"
            if os.path.basename(target) != "":
                target += "/"
            pcl_put_sync(options, source, target)
        elif os.path.isfile(source):
            target = pcl_remote_path(target)
            if not options.skip_hash:
                meta, sha1, md5 = pcl_hash(options, target, True)
            if not (meta and os.path.getsize(source) == meta.size and pcl_check_hash(options, source, sha1, md5)):
                # при удалении в корзину и последующем создании файла с тем же путем он будет восстановлен из корзины и добавлена новая ревизия
                # при таком неочивидном поведении теряется смысл в попытке его удаления
                if meta and not options.trash:
                    pcl_rm(options, meta)
                pcl_put(options, source, target)
        else:
            raise pclError(1, "Unsupported filesystem object: {0}".format(source))
    else:
        pcl_verbose("Skip: {0}".format(source), options.verbose)


def pcl_get_cmd(options, args):
    """
    Обработчик получения файла из хранилища

    Аргументы:
        options (pclOptions) -- Опции приложения
        args    (dict)      -- Аргументы командной строки
    """
    if len(args) < 1:
        raise pclError(1, "Source not specified")
    if len(args) > 2:
        raise pclError(1, "Too many arguments")

    source = pcl_remote_path(args[0])

    if len(args) == 2:
        target = args[1]
    else:
        target = os.path.basename(source)

    ditem, fitem = pcl_stat(options, source)

    if ditem and fitem:
        raise pclError(409, "Undefined behaviour - file AND directory with same name exists")

    if ditem:
        if target == "":
            target = "."
        if os.path.basename(source) != "":
            source += "/"
        if os.path.basename(target) != "":
            target += "/"

        pcl_ensure_local(options, target, "dir")

        pcl_get_sync(options, source, target)

    if fitem:
        exists = pcl_ensure_local(options, target, "file")

        if exists and not options.skip_hash:
            meta, sha1, md5 = pcl_hash(options, source)

        if not exists or not (os.path.getsize(target) == fitem.size and pcl_check_hash(options, target, sha1, md5)):
            pcl_get(options, source, target)


def pcl_download_cmd(options, args):
    """
    Обработчик скачивания файла из интернета в хранилище

    Аргументы:
        options (pclOptions) -- Опции приложения
        args    (dict)       -- Аргументы командной строки
    """
    if len(args) < 1:
        raise pclError(1, "Source not specified")
    if len(args) > 2:
        raise pclError(1, "Too many arguments")

    source = args[0]

    if len(args) == 2:
        target = args[1]
    else:
        target = "/"

    if os.path.basename(target) == "":
        filename = os.path.basename(source)
        if filename == "":
            raise pclError(1, "Can not determine destination file name")

        target += filename

    pcl_download(options, source, pcl_remote_path(target))


def pcl_clean_cmd(options, args):
    """
    Обработчик очистки файлов и директорий

    Аргументы:
        options (pclOptions) -- Опции приложения
        args    (dict)       -- Аргументы командной строки
    """
    if len(args) > 1:
        raise pclError(1, "Too many arguments")

    if len(args) == 1:
        path = args[0]
    else:
        path = "/"

    pcl_clean(options, pcl_remote_path(path))


def pcl_print_usage(cmd = None):
    """
    Вывод справки об использовании приложения и завершение работы

    Аргументы:
        cmd (str) -- Имя команды для которой выводится справка (пустое значение для справки по командам)
    """
    default = pcl_default_config()

    if cmd == None or cmd == "help":
        pcl_print("Usage:")
        pcl_print("     {0} <command> [options] [args]".format(sys.argv[0]))
        pcl_print("")
        pcl_print("Commands:")
        pcl_print("     help     -- describe the usage of this program or its subcommands")
        pcl_print("     token    -- get oauth token for application")
        pcl_print("     info     -- show metainformation about cloud storage")
        pcl_print("     stat     -- show metainformation about cloud object")
        pcl_print("     ls       -- list files and directories")
        pcl_print("     mkdir    -- create directory")
        pcl_print("     rm       -- remove file or directory")
        pcl_print("     mv       -- move file or directory")
        pcl_print("     cp       -- copy file or directory")
        pcl_print("     put      -- upload file to storage")
        pcl_print("     get      -- download file from storage")
        pcl_print("     share    -- publish uploaded object")
        pcl_print("     revoke   -- unpublish uploaded object")
        pcl_print("     download -- download file from internet to storage")
        pcl_print("     clean    -- delete old files and/or directories")
        pcl_print("")
        pcl_print("Options:")
        pcl_print("     --config=<S>  -- config filename (if not default)")
        pcl_print("     --timeout=<N> -- timeout for api requests in seconds (default: {0})".format(default["timeout"]))
        pcl_print("     --retries=<N> -- api call retries count (default: {0})".format(default["retries"]))
        pcl_print("     --delay=<N>   -- api call delay between retries in seconds (default: {0})".format(default["delay"]))
        pcl_print("     --token=<S>   -- oauth token (default: none)")
        pcl_print("     --quiet       -- suppress all errors (default: {0})".format(default["quiet"]))
        pcl_print("     --verbose     -- verbose output (default: {0})".format(default["verbose"]))
        pcl_print("     --debug       -- debug output (default: {0})".format(default["debug"]))
        pcl_print("     --chunk=<N>   -- chunk size in KB for io operations (default: {0})".format(default["chunk"]))
        pcl_print("     --ca-file=<S> -- file with trusted CAs (default: {0})".format("none" if not default["ca-file"] else default["ca-file"]))
        pcl_print("     --ciphers=<S> -- ciphers sute (default: {0})".format("none" if not default["ciphers"] else default["ciphers"]))
        pcl_print("     --version     -- print version and exit")
        pcl_print("")
    elif cmd == "token":
        pcl_print("Usage:")
        pcl_print("     {0} token [code]".format(sys.argv[0]))
        pcl_print("")
    elif cmd == "info":
        pcl_print("Usage:")
        pcl_print("     {0} info".format(sys.argv[0]))
        pcl_print("")
        pcl_print("Options:")
        pcl_print("     --long -- show sizes in bytes instead human-readable format")
        pcl_print("")
    elif cmd == "stat":
        pcl_print("Usage:")
        pcl_print("     {0} stat [object]".format(sys.argv[0]))
        pcl_print("")
        pcl_print(" * If target is not specified, target will be root '/' directory")
        pcl_print("")
    elif cmd == "ls":
        pcl_print("Usage:")
        pcl_print("     {0} ls [options] [path]".format(sys.argv[0]))
        pcl_print("")
        pcl_print("Options:")
        pcl_print("     --human -- human-readable file size")
        pcl_print("     --short -- short format (names only)")
        pcl_print("     --long  -- long format (created, modified, size, name)")
        pcl_print("")
        pcl_print(" * If target is not specified, target will be root '/' directory")
        pcl_print("")
    elif cmd == "mkdir":
        pcl_print("Usage:")
        pcl_print("     {0} mkdir <path1> [path2] ...".format(sys.argv[0]))
        pcl_print("")
    elif cmd == "rm":
        pcl_print("Usage:")
        pcl_print("     {0} rm <object1> [object2] ...".format(sys.argv[0]))
        pcl_print("Options:")
        pcl_print("     --trash -- remove to trash folder (default: {0})".format(default["trash"]))
        pcl_print("")
    elif cmd == "mv":
        pcl_print("Usage:")
        pcl_print("     {0} mv <object1> <object2>".format(sys.argv[0]))
        pcl_print("")
    elif cmd == "cp":
        pcl_print("Usage:")
        pcl_print("     {0} cp <object1> <object2>".format(sys.argv[0]))
        pcl_print("")
    elif cmd == "put":
        pcl_print("Usage:")
        pcl_print("     {0} put <object> [object]".format(sys.argv[0]))
        pcl_print("")
        pcl_print("Options:")
        pcl_print("     --rsync                -- sync remote tree with local")
        pcl_print("     --no-recursion         -- avoid descending in directories (default: {0})".format(default["no-recursion"]))
        pcl_print("     --no-recursion-tag=<S> -- avoid descending in directories containing file (default: {0})".format("none" if not default["no-recursion-tag"] else default["no-recursion-tag"]))
        pcl_print("     --exclude-tag=<S>      -- exclude contents of directories containing file (default: {0})".format("none" if not default["exclude-tag"] else default["exclude-tag"]))
        pcl_print("     --skip-hash            -- skip sha1/md5 integrity checks (default: {0})".format(default["skip-hash"]))
        pcl_print("     --iconv=<S>            -- try to restore file or directory names from the specified encoding if necessary (default: {0})".format("none" if not default["iconv"] else default["iconv"]))
        pcl_print("     --progress             -- show progress")
        pcl_print("")
        pcl_print(" * If target is not specified, target will be root '/' directory")
        pcl_print(" * If target specify a directory (ended with '/'), source file name will be added")
        pcl_print(" * If target file exists, it will be silently overwritten")
        pcl_print(" * Symbolic links are ignored")
        pcl_print("")
    elif cmd == "get":
        pcl_print("Usage:")
        pcl_print("     {0} get <object> [object]".format(sys.argv[0]))
        pcl_print("")
        pcl_print("Options:")
        pcl_print("     --rsync        -- sync local tree with remote")
        pcl_print("     --no-recursion -- avoid descending automatically in directories (default: {0})".format(default["no-recursion"]))
        pcl_print("     --skip-hash    -- skip sha1/md5 integrity checks (default: {0})".format(default["skip-hash"]))
        pcl_print("     --progress     -- show progress")
        pcl_print("")
        pcl_print(" * If target is not specified, source file name will be used")
        pcl_print(" * If target exists, it will be silently overwritten")
        pcl_print("")
    elif cmd == "share":
        pcl_print("Usage:")
        pcl_print("     {0} share <object1> [object2] ...".format(sys.argv[0]))
        pcl_print("")
    elif cmd == "revoke":
        pcl_print("Usage:")
        pcl_print("     {0} revoke <object1> [object2] ...".format(sys.argv[0]))
        pcl_print("")
    elif cmd == "download":
        pcl_print("Usage:")
        pcl_print("     {0} download <URL> [object]".format(sys.argv[0]))
        pcl_print("")
        pcl_print(" * If target is not specified, target will be root '/' directory with file name extracted from URL (if possible).")
        pcl_print("")
    elif cmd == "clean":
        pcl_print("Usage:")
        pcl_print("     {0} clean <options> [object]".format(sys.argv[0]))
        pcl_print("")
        pcl_print("Options:")
        pcl_print("     --dry      -- just print list of object to delete (default: {0})".format(default["dry"]))
        pcl_print("     --type=<S> -- type of objects - 'file', 'dir' or 'all' (default: {0})".format(default["type"]))
        pcl_print("     --keep=<S> -- keep criteria (default: none):")
        pcl_print("                   * date ('2014-02-12T12:19:05+04:00')")
        pcl_print("                   * relative interval ('7d', '4w', '1m', '1y')")
        pcl_print("                   * number of objects ('31')")
        pcl_print("")
        pcl_print(" * If target is not specified, target will be root '/' directory")
        pcl_print(" * Objects sorted and filtered by modified date (not created date)")
        pcl_print("")
    else:
        sys.stderr.write("Unknown command {0}\n".format(cmd))
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    argc = len(sys.argv)
    if argc < 2:
        pcl_print_usage()

    regexp  = re.compile("--config=(.*)")
    cfgfile = [match.group(1) for arg in sys.argv for match in [regexp.search(arg)] if match]

    if len(cfgfile) == 0:
        cfgfile = os.path.expanduser("~") + "/.{0}.cfg".format(__title__)
    else:
        cfgfile = cfgfile[0]

    args   = []
    config = pcl_load_config(cfgfile)
    regexp = re.compile("^--(\S+?)(=(.*)){,1}$")
    for i in range(1, argc):
        arg = sys.argv[i]
        opt = regexp.split(arg)
        if len(opt) == 5:
            if opt[3] == None:
                opt[3] = True
            config[opt[1].lower()] = opt[3]
        else:
            args.append(arg)

    if "version" in config:
        pcl_print("{0} v{1}".format(__title__, __version__))
        sys.exit(0)

    if len(args) == 0:
        pcl_print_usage()

    options = pclOptions(config)

    command = args.pop(0).lower()
    if command == "help":
        command = None
        if len(args) == 1:
            command = args.pop(0).lower()
        pcl_print_usage(command)

    if options.cafile == None:
        pcl_verbose("Unsafe HTTPS connection - ca-file not used", options.verbose)

    # TODO: cp for directory (pcl_cp_dir)
    # TODO: revoke (pcl_unpublish)
    # TODO: download, du, restore
    # TODO: wait to fix pCloud bug with trash_clear
    try:
        if command == "token":
            pcl_token_cmd(options, args)
        elif command == "info":
            pcl_info_cmd(options, args)
        elif command == "stat":
            pcl_stat_cmd(options, args)
        elif command == "ls":
            pcl_ls_cmd(options, args)
        elif command == "mkdir":
            pcl_mkdir_cmd(options, args)
        elif command == "rm":
            pcl_rm_cmd(options, args)
        elif command == "mv":
            pcl_mv_cmd(options, args)
        elif command == "cp":
            pcl_cp_cmd(options, args)
        elif command == "put":
            pcl_put_cmd(options, args)
        elif command == "get":
            pcl_get_cmd(options, args)
        elif command == "share":
            pcl_share_cmd(options, args)
        elif command == "revoke":
            pcl_revoke_cmd(options, args)
        elif command == "download":
            pcl_download_cmd(options, args)
        elif command == "clean":
            pcl_clean_cmd(options, args)
        else:
            pcl_print_usage(command)
    except pclError as e:
        if not options.quiet:
            sys.stderr.write("{0}\n".format(e.errmsg))
        if e.errno < 256:
            sys.exit(e.errno)
        elif e.errno < 1000:
            sys.exit(int(e.errno / 100))
        else:
            sys.exit(int(e.errno / 1000) * 10)
    except pclCertError as e:
        if not options.quiet:
            sys.stderr.write("{0}\n".format(e))
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(1)
