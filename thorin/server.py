import time
import json
import cgi
import threading
import os.path
import re
import sys
import logging
import lesscpy

from six import StringIO
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from http.cookies import SimpleCookie
from urllib.parse import unquote, quote


def get_cookies(headers):
    """
    Convert cookies string to dict
    """
    cookies_res = {}
    try:
        cookies = headers['Cookie'].split(';')
        for cookie in cookies:
            c = cookie.split('=')
            cookies_res[c[0].strip()] = unquote(c[1].strip())
    except Exception as e:
        logging.debug('get_cookies() %s' % e)

    return cookies_res

def get_params(path):
    """
    Convert params from path to dict
    ex: '?page=1&language=en' to dict
    """

    query_res = {}
    if path.find('?') != -1:
        query = path[path.find('?')+1:]
        if query.find('&') != -1:
            query_arr = query.split('&')
            for q in query_arr:
                v = q.split('=')
                if len(v) == 2:
                    query_res[v[0].strip()] = unquote(v[1].strip())
        else:
            v = query.split('=')
            if len(v) == 2:
                query_res[v[0].strip()] = unquote(v[1].strip())

    return query_res


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""
    request_queue_size = 1000


class Middleware:
    """
    Singleton
    Abstract layer between request and custom handler
    For example:
    protect only auth page, ddos, add some data (like BEFORE REQUEST)
    """

    def __init__(self):
        self.middlewares = []

    def add(self, class_obj):
        self.middlewares.append(class_obj)

    def use(self, req):
        req_result = req
        for m in self.middlewares:
            req_result = m(req_result)
            if not req_result:
                break

        return req_result


class StaticContentHandler:
    """
    Return static files: js, css, images
    CSS: By default StaticContentHandler using LESS, but you can use raw css
    this class can handle css files like some.css and less like some.less
    (prod mode) less files cached after first call and saved memory while Thorin working.
    (dev mode) reload less files each request.
    you can use GULP, GRUNT or another build system to merge and create less, styl, jade or somthing other.
    """
    def __init__(self, req):
        self.req = req

        mimetype_res = self.mimetype()

        if mimetype_res['send_reply']:
            try:
                ext_list = ['jpg', 'gif', 'png']

                if mimetype_res['mimetype'] == 'text/css':
                    content = self.css()
                    if not content:
                        raise IOError
                else:
                    if any(mimetype_res['mimetype'].find(ext) != -1 for ext in ext_list):
                        f = open('.'+self.req.path, 'rb')
                    else:
                        f = open('.'+self.req.path)
                    content = f.read()
                    f.close()

                self.req.send_response(200)
                self.req.send_header("Content-type", mimetype_res['mimetype'])
                self.req.end_headers()

                if any(mimetype_res['mimetype'].find(ext) != -1 for ext in ext_list):
                    self.req.wfile.write(content)
                else:
                    self.req.wfile.write(bytes(content, "utf-8"))
            except IOError:
                self.req.send_error(404)
        else:
            self.req.send_error(404)

    def css(self):
        content = None

        path = '.'+self.req.path
        if os.path.isfile(path):
            f = open(path)
            content = f.read()
            f.close()
        else:
            path = re.sub('(\.css)', '.less', path, flags=re.IGNORECASE)
            if os.path.isfile(path):
                f = open(path)
                f_content = f.read()
                f.close()

                for l in thorinService.less_list:
                    if l['path'] == path:
                        content = l['css']
                        break

                if not content:
                    content = lesscpy.compile(StringIO(f_content), minify=True)
                    if thorinService.env.get('location') and thorinService.env['location'] == 'prod':
                        thorinService.less_list.append({
                            'path': path,
                            'css': content
                        })

        return content

    def mimetype(self):
        mimetype = 'text/plain'

        send_reply = False
        if self.req.path.endswith(".html"):
            mimetype = 'text/html'
            send_reply = True
        if self.req.path.endswith(".jpg"):
            mimetype = 'image/jpg'
            send_reply = True
        if self.req.path.endswith(".gif"):
            mimetype = 'image/gif'
            send_reply = True
        if self.req.path.endswith(".png"):
            mimetype = 'image/png'
            send_reply = True
        if self.req.path.endswith(".js"):
            mimetype = 'application/javascript'
            send_reply = True
        if self.req.path.endswith(".css"):
            mimetype = 'text/css'
            send_reply = True

        return {
            'mimetype': mimetype,
            'send_reply': send_reply
        }


class Router:
    """
    Singleton
    Router can handle http requests like this:
    GET /user/:id # in req.params you can get user_id req.params['id']
    GET /user/:id? # if you add "?" this param optional
    POST /event/create
    PUT /events/type/:type?/page/:page you can use optional param anywhere
    I was insperied expressjs(nodejs) framework and get simillar format
    """
    def __init__(self):
        self.routes = []

    def add(self, method, path, handler, action, middleware = None):
        self.routes.append({
            'path': path, # route path. Ex. /user/:id
            'method': method, # GET, POST, etc
            'handler': handler, # controller name. Ex. IndexController
            'action': action, # method name of controller (string), 'get_user'
            'middleware': middleware # method or function in list. Ex. [IndexController.is_user_auth]
        })

    def show_error_page(self, req, code):
        req.send_response(code)
        req.send_header("Content-type", "text/html")
        req.end_headers()

        try:
            f = open(thorinService.error_folder+'/'+str(code)+'.html')
            html = f.read()
            req.wfile.write(bytes(html, "utf-8"))
            f.close()
        except:
            pass

    def get_params(self, path, route_path):
        """
        get all values from path
        return dict { param_name: value, ... }
        """

        def get_clean_key(key):
            return re.sub('\?', '', key).strip()

        params = {}

        path = re.sub('&#58;', ':', path)

        path_list = path.split('/')
        route_path_list = route_path.split('/')

        index = 0
        for r in route_path_list:
            if r.find(':') != -1:
                key = get_clean_key(r[1:])
                try:
                    params[key] = path_list[index]
                except IndexError:
                    pass
            index += 1

        return params

    def is_param_in_another_route(self, index, param):
        res = False
        for r in self.routes:
            try:
                path = r['path'].split('/')
                if path[index] == param:
                    res = True
                    break
            except:
                pass
        return res


    def get_current_route(self, req):
        """ find and get current route """
        current_route = None
        params = {}

        req.path = re.sub('\:', '&#58;', req.path)

        if len(req.path) > 1 and req.path[-1:] == '/':
            req.path = req.path[:-1]

        for route in self.routes:
            found = True

            # if route equal path (doesn`t has params in route)
            if req.path == route['path'] and req.command == route['method']:
                current_route = route
                break
            # if route has params
            elif ':' in route['path']:
                route_path = route['path'].split('/')

                req_path = req.path.split('/')
                req_path_index = 0
                for route_param in route_path:
                    try:
                        # route has optional param
                        if '?' in route_param:
                            continue
                        elif route_param != req_path[req_path_index]:
                            if ':' not in route_param:
                                found = False
                                break
                            else:
                                if self.is_param_in_another_route(req_path_index, req_path[req_path_index]):
                                    found = False
                                    break
                        req_path_index += 1
                    except Exception as e:
                        logging.debug('Route error %s' % e)
                        found = False
                        break

                # found route and method(get,post,etc)
                if found and req.command == route['method']:
                    current_route = route
                    break

        if current_route:
            logging.debug('current_route %s %s' % (current_route, req.path))
            params = self.get_params(req.path, current_route['path'])

        return {
            'route': current_route,
            'params': params
        }

    def use_middlewares(self, req, original_req, current_route):
        """
        start current middleware
        main feature - if (request == None) after executing middleware
        it`s protected middleware and we send 403 error to client
        """
        protected = False
        for mid in current_route['middleware']:
            req = mid(req)
            if not req:
                protected = True
                break

        if not protected:
            r = current_route['handler'](req)
            getattr(r, current_route['action'])()
        else:
            self.show_error_page(original_req, 403)

    def start_handler(self, req):
        if not req:
            return None

        # save original request
        # if middleware return None our request be overrided
        original_req = req
        current_route = self.get_current_route(req)

        if current_route['route']:
            req.params = current_route['params']
            if not current_route['route']['middleware']:
                r = current_route['route']['handler'](req)
                getattr(r, current_route['route']['action'])()
            else:
                self.use_middlewares(req, original_req, current_route['route'])
        else:
            self.show_error_page(original_req, 404)

    def handler(self, req):
        """
        first method called from MainHandler class.
        we are create new thread and processing client request.
        each one request create new thread.
        """
        t = threading.Thread(target=self.start_handler, args=(req,))
        t.start()
        # forward processed request
        t.join()


class MainHandler(BaseHTTPRequestHandler):
    """ Using BaseHTTPRequestHandler from default Python3 box """
    def __init__(self, request, client_address, server):
        """
        override default baseHTTP info
        add some variables like: cookies, query, path, etc.
        """
        self.server_version = 'Thorin/1.0.3'
        self.request_version = 'HTTP/1.1'
        self.sys_version = ''
        self.response_time = time.time()
        self.cookies = {}
        self.query = {}
        self.path = {}
        self.remote_ip = ''

        BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def add_request_data(self, s):
        # Get real ip from headers
        if s.headers.get(thorinService.remote_real_ip_header):
            s.remote_ip = s.headers[thorinService.remote_real_ip_header]
        # Convert cookies to dict
        s.cookies = get_cookies(s.headers)
        # Convert params to dict
        s.query = get_params(s.path)
        # Remove params from request path.
        # Because we want get clear path. Then we define path in routes
        if s.path.find('?') != -1:
            s.path = s.path[0:s.path.find('?')]

    def do_GET(self):
        self.add_request_data(self)

        # if this static folder. Call StaticContentHandler
        if self.path.find(thorinService.static_folder) == 0:
            StaticContentHandler(self)
        else:
            router.handler(middleware.use(self))

    def do_POST(self):
        self.add_request_data(self)
        router.handler(middleware.use(self))

    def do_PUT(self):
        self.add_request_data(self)
        router.handler(middleware.use(self))

    def do_PATCH(self):
        self.add_request_data(self)
        router.handler(middleware.use(self))

    def do_DELETE(self):
        self.add_request_data(self)
        router.handler(middleware.use(self))

    def log_message(self, format, *args):
        self.response_time = round(time.time() - self.response_time, 3)
        logging.info('%s - [%s] %s - %sms' % (self.remote_ip, self.log_date_time_string(), format%args, self.response_time))


class ThorinServer:
    """ Main Init Server Class """

    def __init__(self):
        self.my_server = None

    def start(self, host_name='localhost', port_number='9000'):
        """ start listen host:port """
        self.host_name = host_name
        self.port_number = port_number
        # start threaded server. Each request processing by new thread.
        # start MainHandler class
        self.my_server = ThreadedHTTPServer((self.host_name, self.port_number), MainHandler)
        logging.info("%s Server Starts - %s:%s" % (time.asctime(), self.host_name, self.port_number))

        try:
            self.my_server.serve_forever()
        except KeyboardInterrupt:
            pass

        self.my_server.server_close()
        logging.info("%s Server Stops - %s:%s" % (time.asctime(), self.host_name, self.port_number))


class ThorinUtils:
    """
    this class extend custom controllers
    like this:
    class IndexController(ThorinUtils):
      def __init__(self):
        ...
        ...
    ThorinUtils can:
    post_data - return post data from forms, POST ajax, etc.
    send - return template with data, json format or text/html, etc.
    redirect - redirct user to another page
    set_cookie - set cookie :)
    remove_cookie - delete cookie :)
    """
    def __init__(self, req):
        self.req = req
        self.cookies_list = []

    def post_data(self):
        """ post_data return data from Forms, post ajax, etc """
        form = cgi.FieldStorage(
            fp=self.req.rfile,
            headers=self.req.headers,
            environ={
                'REQUEST_METHOD': 'POST',
                'CONTENT_TYPE': self.req.headers['Content-Type'],
            }
        )

        return form

    def send(self, data={}, code=200, content_type='text/html', path_to_template=''):
        """ send data with template to client or send text/html, application/json """

        # send cookies
        self.req.send_response(code)
        self.req.send_header("Content-type", content_type)
        for c in self.cookies_list:
            self.req.send_header('Set-Cookie', c.output(header=''))
        self.req.end_headers()

        try:
            if content_type == 'text/html':
                # if you connect templater Jinga2 or another
                if thorinService.t_engine and thorinService.t_engine_render:
                    # static_data it`s enviroment variables, path to css, js, etc
                    data['static_data'] = thorinService.static_data
                    # Access to cookies. You can call cookie variable in template
                    data['cookies'] = self.req.cookies
                    # Access to params. All sended params you can show in template
                    data['params'] = self.req.params

                    result_data = thorinService.t_engine_render(path_to_template, data)
                    self.req.wfile.write(bytes(result_data, "utf-8"))
                else:
                    # send raw text/html data
                    # example: '<b>hello</b>'
                    self.req.wfile.write(bytes(data, "utf-8"))
            elif content_type == 'application/json':
                # send json string to client
                json_str = json.dumps(data, ensure_ascii=False)
                self.req.wfile.write(bytes(json_str, "utf-8"))
        except BrokenPipeError as e:
            print('########################################')
            logging.debug('BrokenPipeError. Connection was broken. %s' % e)

    def redirect(self, url):
        """ redirect to another page """
        self.req.send_response(301)
        for c in self.cookies_list:
            self.req.send_header('Set-Cookie', c.output(header=''))
        self.req.send_header('Location', url)
        self.req.end_headers()

    def set_cookie(self, name, value, path='/', expires='Wed, 13 Jan 2020 10:00:00 GMT'):
        """ set cookie with SimpleCookie() standart python3 class """
        c = SimpleCookie()
        c[name] = quote(value)
        c[name]['path'] = path
        c[name]['expires'] = expires
        self.cookies_list.append(c)

    def remove_cookie(self, name):
        c = SimpleCookie()
        c[name] = 'deleted'
        c[name]['expires'] = 'Thu, 01 Jan 1970 00:00:00 GMT'
        self.cookies_list.append(c)


class ThorinService:
    """
    Singleton
    wrapper for creating middlewares and routes
    storage for db connection, env variables, path to static folder, etc
    """
    def __init__(self):
        # you can save all env right here or use self.glob
        self.env = {}
        # default language project
        self.lang = 'ru'
        # database dict. You can create many different links to DB
        # example:
        # thorinSerivce.db['mysql'] = connect_to_mysql()
        # thorinSerivce.db['mongo'] = connect_to_mongo()
        self.db = {}
        # if you working under Nginx you should specify real user ip.
        # nginx directive which is responsible for ip address:
        # proxy_set_header X-Real-IP $remote_addr;
        # Why "X-Real-IP" - I don`t know. I took this along time ago from stackoverflow discussion
        self.remote_real_ip_header = 'X-Real-IP'
        # you can set any variable in dict static_data
        self.static_data = {
            'domain': ''
        }
        # storage for global variables
        # project serphi.com stores there cached events, prices, etc
        self.glob = {}
        # path to static folder (js, css, fonts)
        self.static_folder = '/static'
        # template engine
        self.t_engine = None
        # template engine render
        self.t_engine_render = None
        # less (css) files list
        self.less_list = []
        # error folder
        # example: 404.html, 502.html, etc
        self.error_folder = './templates/errors'
        # settings for cookies
        self.cookies = {
            'httpOnly': True,
            'Secure': False
        }

    # wrapper to add middleware
    def add_middleware(self, class_obj):
        middleware.add(class_obj)

    # wrapper to add route
    def add_route(self, method, path, handler, action, middleware = None):
        router.add(method, path, handler, action, middleware)

router = Router()
middleware = Middleware()
thorinService = ThorinService()
