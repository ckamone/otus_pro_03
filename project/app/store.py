import random
import redis

class Storage():
    def __init__(self) -> None:
        self.redis_client = redis.Redis()

    def cache_get(self, key):
        self.redis_client.get(key)

    def cache_set(self, key, value, store_time):
        self.redis_client.set(key, value)
        self.redis_client.expire(key, store_time)

    
    def get(self, key):
        interests = ["cars", "pets", "travel", "hi-tech",
                    "sport", "music", "books", "tv",
                    "cinema", "geek", "otus"]
        x = "%s" % random.sample(interests, 2)
        return x.replace("'", '"')