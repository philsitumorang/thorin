import json
import threading
import urllib.request
import urllib.parse
import unittest
from server import ThorinServer, ThorinUtils, thorinService
import time

class IndexController(ThorinUtils):

    def get_raw_html(self):
        self.send('<b>hello world</b>')

    def test_main_middleware(self):
        self.send(self.req.middleware_var)

    def test_route_middleware(self):
        self.send(self.req.route_middleware_var)

    def test_route_failed_middleware(self):
        self.send('This message not showed')

    def test_not_found_page(self):
        self.send('This message not showed')

    def test_post_request(self):
        post_data = self.post_data()
        t1 = post_data.getvalue('test_value_1')
        t2 = post_data.getvalue('test_value_2')
        self.send(t1 + ' ' + t2)

    def test_put_request(self):
        post_id = self.req.params['id']
        self.send(post_id)

    def test_patch_request(self):
        post_id = self.req.params['id']
        self.send(post_id)

    def test_delete_request(self):
        post_id = self.req.params['id']
        self.send(post_id)

    def test_wrong_method_request(self):
        self.send('This message not showed')

    def test_optional_param(self):
        country = None
        city = None

        if self.req.params.get('country'):
            country = self.req.params['country']
        if self.req.params.get('city'):
            city = self.req.params['city']

        post_id = self.req.params['id']

        result = {
            'country': country,
            'city': city,
            'post_id': post_id
        }
        self.send(result, content_type="application/json")


class TestSequenceFunctions(unittest.TestCase):

    def test_get_index_page(self):
        f = urllib.request.urlopen('http://localhost:9000')
        data = f.read().decode('utf8')
        self.assertEqual('<b>hello world</b>', data)

    def test_main_middleware(self):
        f = urllib.request.urlopen('http://localhost:9000/test_main_middleware')
        data = f.read().decode('utf8')
        self.assertEqual('main middleware processed', data)

    def test_route_middleware(self):
        f = urllib.request.urlopen('http://localhost:9000/test_route_middleware')
        data = f.read().decode('utf8')
        self.assertEqual('route middleware', data)

    def test_route_failed_middleware(self):
        try:
            f = urllib.request.urlopen('http://localhost:9000/test_route_failed_middleware')
            data = f.read().decode('utf8')
        except urllib.error.HTTPError as e:
            self.assertEqual(403, e.code)

    def test_not_found_page(self):
        try:
            f = urllib.request.urlopen('http://localhost:9000/test_not_found_page')
            data = f.read().decode('utf8')
        except urllib.error.HTTPError as e:
            self.assertEqual(404, e.code)

    def test_post_request(self):
        url = 'http://localhost:9000'
        values = {'test_value_1' : 'hello',
                  'test_value_2' : 'world!'}

        data = urllib.parse.urlencode(values)
        data = data.encode('utf-8') # data should be bytes
        req = urllib.request.Request(url, data)
        resp = urllib.request.urlopen(req)
        respData = resp.read().decode('utf8')
        self.assertEqual('hello world!', respData)

    def test_put_request(self):
        req = urllib.request.Request('http://localhost:9000/post/973', method='PUT')
        f = urllib.request.urlopen(req)
        data = f.read().decode('utf8')
        self.assertEqual('973', data)

    def test_patch_request(self):
        req = urllib.request.Request('http://localhost:9000/post/973', method='PATCH')
        f = urllib.request.urlopen(req)
        data = f.read().decode('utf8')
        self.assertEqual('973', data)

    def test_delete_request(self):
        req = urllib.request.Request('http://localhost:9000/post/93274', method='DELETE')
        f = urllib.request.urlopen(req)
        data = f.read().decode('utf8')
        self.assertEqual('93274', data)

    def test_wrong_method_request(self):
        try:
            req = urllib.request.Request('http://localhost:9000/post/93274', method='WRONG')
            f = urllib.request.urlopen(req)
            data = f.read().decode('utf8')
        except urllib.error.HTTPError as e:
            self.assertEqual(501, e.code)

    def test_optional_param(self):
        f = urllib.request.urlopen('http://localhost:9000/post/5321')
        data = f.read().decode('utf8')
        dict_obj = json.loads(data)
        self.assertEqual(dict_obj['post_id'], '5321')
        self.assertEqual(dict_obj['country'], None)
        self.assertEqual(dict_obj['city'], None)

        f = urllib.request.urlopen('http://localhost:9000/post/232/1')
        data = f.read().decode('utf8')
        dict_obj = json.loads(data)
        self.assertEqual(dict_obj['post_id'], '232')
        self.assertEqual(dict_obj['country'], '1')
        self.assertEqual(dict_obj['city'], None)

        f = urllib.request.urlopen('http://localhost:9000/post/232/1/Moscow')
        data = f.read().decode('utf8')
        dict_obj = json.loads(data)
        self.assertEqual(dict_obj['post_id'], '232')
        self.assertEqual(dict_obj['country'], '1')
        self.assertEqual(dict_obj['city'], 'Moscow')

        f = urllib.request.urlopen('http://localhost:9000/post/2320909090909/hm:what/:some:words')
        data = f.read().decode('utf8')
        dict_obj = json.loads(data)
        self.assertEqual(dict_obj['post_id'], '2320909090909')
        self.assertEqual(dict_obj['country'], 'hm:what')
        self.assertEqual(dict_obj['city'], ':some:words')


def start_server():
    thorin.start('localhost', 9000)

def simple_middleware(req):
    req.middleware_var = 'main middleware processed'
    return req

def route_middleware(req):
    req.route_middleware_var = 'route middleware'
    return req

def route_failed_middleware(req):
    return None

thorin = ThorinServer()

thorinService.add_middleware(simple_middleware)
thorinService.add_route('GET', '/', IndexController, "get_raw_html")
thorinService.add_route('GET', '/test_main_middleware', IndexController, "test_main_middleware")
thorinService.add_route('GET', '/test_not_found_page', IndexController, "test_not_found_page")
thorinService.add_route('GET', '/test_route_middleware', IndexController, "test_route_middleware", [route_middleware])
thorinService.add_route('GET', '/test_route_failed_middleware', IndexController, "test_route_failed_middleware", [route_failed_middleware])
thorinService.add_route('POST', '/', IndexController, "test_post_request")
thorinService.add_route('PUT', '/post/:id', IndexController, "test_put_request")
thorinService.add_route('PATCH', '/post/:id', IndexController, "test_patch_request")
thorinService.add_route('DELETE', '/post/:id', IndexController, "test_delete_request")
thorinService.add_route('WRONG', '/post/:id', IndexController, "test_wrong_method_request")
thorinService.add_route('GET', '/post/:id/:country?/:city?', IndexController, "test_optional_param")

t = threading.Thread(target=start_server)
t.start()

time.sleep(1)
suite = unittest.TestLoader().loadTestsFromTestCase(TestSequenceFunctions)
unittest.TextTestRunner(verbosity=2).run(suite)
