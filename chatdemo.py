#!/usr/bin/env python
import os
import logging
import tornado.auth
import tornado.escape
import tornado.ioloop
import tornado.web
import os
import os.path
import uuid

from tornado import gen
from tornado.options import define, options, parse_command_line

define("port", default=8888, help="run on the given port", type=int)


class MessageBuffer(object):
    def __init__(self):
        self.waiters = set()
        self.cache = []
        self.cache_size = 200

    def wait_for_messages(self, callback, cursor=None):
        if cursor:
            new_count = 0
            for msg in reversed(self.cache):
                if msg["id"] == cursor:
                    break
                new_count += 1
            if new_count:
                callback(self.cache[-new_count:])
                return
        self.waiters.add(callback)

    def cancel_wait(self, callback):
        self.waiters.remove(callback)

    def new_messages(self, messages):
        logging.info("Sending new message to %r listeners", len(self.waiters))
        for callback in self.waiters:
            try:
                callback(messages)
            except:
                logging.error("Error in waiter callback", exc_info=True)
        self.waiters = set()
        self.cache.extend(messages)
        if len(self.cache) > self.cache_size:
            self.cache = self.cache[-self.cache_size:]


message_buffers = {}


class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        user_json = self.get_secure_cookie("chatdemo_user")
        if not user_json: return None
        return tornado.escape.json_decode(user_json)


class MainHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        self.render("index.html", rooms=message_buffers.keys())


class MessageNewHandler(BaseHandler):
    @tornado.web.authenticated
    def post(self):
        message = {
            "id": str(uuid.uuid4()),
            "from": '@' + self.current_user["username"],
            "body": self.get_argument("body"),
        }
        # to_basestring is necessary for Python 3's json encoder,
        # which doesn't accept byte strings.
        message["html"] = tornado.escape.to_basestring(
            self.render_string("message.html", message=message))
        if self.get_argument("next", None):
            self.redirect(self.get_argument("next"))
        else:
            self.write(message)
        message_buffers[self.get_argument("room")].new_messages([message])


class MessageUpdatesHandler(BaseHandler):
    @tornado.web.authenticated
    @tornado.web.asynchronous
    def post(self):
        cursor = self.get_argument("cursor", None)
        self.room = self.get_argument("room")
        message_buffers[self.room].wait_for_messages(self.on_new_messages,
                                                cursor=cursor)

    def on_new_messages(self, messages):
        # Closed client connection
        if self.request.connection.stream.closed():
            return
        self.finish(dict(messages=messages))

    def on_connection_close(self):
        message_buffers[self.room].cancel_wait(self.on_new_messages)


class AuthLoginHandler(BaseHandler, tornado.auth.TwitterMixin):
  @tornado.web.asynchronous
  def get(self):
    if self.get_argument("oauth_token", None):
      self.get_authenticated_user(self.async_callback(self._on_auth))
      return
    self.authorize_redirect("/auth/login")

  def _on_auth(self, user):
    if not user:
      raise tornado.web.HTTPError(500, "Twitter auth failed")
    self.set_secure_cookie("chatdemo_user", tornado.escape.json_encode(user))
    self.redirect("/")


class AuthLogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie("chatdemo_user")
        self.write("You are now logged out")


class RoomsHandler(BaseHandler):
    def get(self):
        self.render("rooms.html", rooms=message_buffers.keys())
    def post(self):
        room = self.get_argument("room", None)
        if room is not None:
            self.redirect("/rooms/" + room.lower())
        else:
            self.redirect("/")


class RoomHandler(BaseHandler):
    def get(self, room):
        if room not in message_buffers:
            message_buffers[room] = MessageBuffer()
        self.render("room.html", room=room, messages=message_buffers[room].cache)


def main():
    parse_command_line()
    app = tornado.web.Application(
        [
            (r"/", MainHandler),
            (r"/auth/login", AuthLoginHandler),
            (r"/auth/logout", AuthLogoutHandler),
            (r"/a/message/new", MessageNewHandler),
            (r"/a/message/updates", MessageUpdatesHandler),
            (r"/rooms", RoomsHandler),
            (r"/rooms/([a-z0-9_]+)", RoomHandler),
            ],
        cookie_secret="XD8BWhuTLgpzWKLtNiRjsGRhNwQqW7lXyS16AJXdmFv7WdZZYP",
        login_url="/auth/login",
        template_path=os.path.join(os.path.dirname(__file__), "templates"),
        static_path=os.path.join(os.path.dirname(__file__), "static"),
        xsrf_cookies=True,
        debug=(os.environ.get('DEBUG', 'false') == 'true'),
        twitter_consumer_key=os.environ["TWITTER_CONSUMER_KEY"],
        twitter_consumer_secret=os.environ["TWITTER_CONSUMER_SECRET"]
        )
    app.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()


if __name__ == "__main__":
    main()
