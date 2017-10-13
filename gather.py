#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
#   filtered-js-gatherer - Scripts for MWSCup 2017
#   https://github.com/h-uekawa/filtered-js-gatherer
#
#   Copyright (c) 2017 Team Security Anthem (Okayama Univ.)
#   Released under the MIT License, see LICENSE.txt
#
##

import sys
from tweepy.streaming import StreamListener
from tweepy import OAuthHandler
from tweepy import Stream
from threading import BoundedSemaphore
from threading import Thread
from time import sleep
import requests
from html.parser import HTMLParser
from urllib.parse import urljoin
from adblockparser import AdblockRules
from hashlib import sha1
from os import makedirs
from os.path import exists
from datetime import datetime

consumer_key = "xxxxxxxxxxxxxxxxxxxxxxxxx"
consumer_secret = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
access_token = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
access_token_secret = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

max_url_list_size = 1000
http_timeout = 5
user_agent = "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)"
rule_file = "./easylist.txt"
js_dir = "./js/"
js_list_file = "./list.tsv"

fetched_pages = 0
fetched_jses = 0

class UrlList:
	def __init__(self, max=None, filter=None):
		self.list = list()
		self.max = max_url_list_size
		self.sem = BoundedSemaphore()
		self.filter = filter
	
	def append(self, url):
		try:
			url = url[:url.index("#")]
		except:
			pass
		
		with self.sem:
			if url in self.list:
				return
			
			if self.filter and not self.filter(url):
				return
			
			if not self.max is None and len(self.list) >= self.max:
				self.list.pop(0)
			
			self.list.append(url)
	
	def pop(self):
		while True:
			self.sem.acquire()
			if len(self.list) > 0:
				break
			self.sem.release()
			sleep(1.0)
		url = self.list.pop(0)
		self.sem.release()
		return url
	
	def has(self, url):
		with self.sem:
			return url in self.list

class UrlListener(StreamListener):
	
	def __init__(self, cb, *a, **ka):
		super().__init__(*a, **ka)
		self.url_cb = cb
	
	def on_status(self, status):
		for url in status.entities["urls"]:
			self.url_cb(url["expanded_url"])

def url_filter(url):
	if url.startswith("https://twitter.com/"):
		return False
	if url.startswith("https://www.youtube.com/"):
		return False
	if url.startswith("https://youtu.be/"):
		return False
	if url.startswith("http://youtu.be/"):
		return False
	return True

def gather_urls(auth, urls): # thread
	while True:
		try:
			stream = Stream(auth, UrlListener(lambda u:urls.append(u)))
			stream.filter(track=["http"]) # "https"
		except:
			sleep(60)

def fetch_page(url):
	global fetched_pages
	fetched_pages += 1
	
	headers = { "User-Agent": user_agent }
	
	r = requests.head(url, timeout=http_timeout, headers=headers)
	if not r.headers["content-type"].startswith("text/html"):
		raise
	
	r = requests.get(url, timeout=http_timeout, headers=headers)
	if r.status_code != 200:
		raise
	
	return r.text

class MyHTMLParser(HTMLParser):
	
	def __init__(self, cb, *a, **ka):
		super().__init__(*a, **ka)
		self.src_cb = cb
	
	def handle_starttag(self, tag, attrs):
		if tag == "script":
			for (a,v) in attrs:
				if a == "src":
					self.src_cb(v)

def extract_js_urls(html, page_url):
	js_urls = list()
	def add_src(src):
		url = urljoin(page_url, src)
		if not url in js_urls:
			js_urls.append(url)
	
	p = MyHTMLParser(add_src)
	try:
		p.feed(html)
	except:
		pass
	
	return js_urls

def fetch_js(url):
	global fetched_jses
	fetched_jses += 1
	
	headers = { "User-Agent": user_agent }
	
	r = requests.get(url, timeout=http_timeout, headers=headers)
	if r.status_code != 200:
		raise
	
	return r.content

def save_js(js, fetch_time, js_url, page_url, user_agent):
	hash = sha1(js).hexdigest()
	
	makedirs(js_dir, exist_ok=True)
	
	file = "%s/%s"%(js_dir,hash)
	if not exists(file):
		open(file, "wb").write(js)
	
	with open(js_list_file, "a") as f:
		timestr = fetch_time.isoformat(" ")
		info = [hash, timestr, js_url, page_url, user_agent]
		print("\t".join(info), file=f)

def crawl_urls(urls, saved, rules): # thread
	while True:
		page_url = urls.pop()
		
		try:
			html = fetch_page(page_url)
		except:
			continue
		finally:
			sleep(1.0)
		
		js_urls = extract_js_urls(html, page_url)
		
		for js_url in js_urls:
			if not rules.should_block(js_url, {"script": True}):
				continue
			
			if saved.has(js_url):
				continue
			
			try:
				print(js_url, end="\033[K\n")
				fetch_time = datetime.now()
				js = fetch_js(js_url)
			except:
				continue
			
			save_js(js, fetch_time, js_url, page_url, user_agent)
			saved.append(js_url)

def main(urlfile=None):
	rules = AdblockRules(open(rule_file).read().splitlines())
	
	urls = UrlList(max=max_url_list_size, filter=url_filter)
	saved = UrlList()
	
	if urlfile:
		urls.list = open(urlfile, "r").read().splitlines()
		
	else:
		auth = OAuthHandler(consumer_key, consumer_secret)
		auth.set_access_token(access_token, access_token_secret)
		
		gt = Thread(target=gather_urls, args=(auth,urls))
		gt.start()
	
	cts = []
	for i in range(6):
		ct = Thread(target=crawl_urls, args=(urls,saved,rules))
		cts.append(cts)
		ct.start()
	
	global fetched_pages, fetched_jses
	while True:
		print("[pages] queued:%d fetched:%d [js] fetched:%d saved:%d"%(
			len(urls.list),fetched_pages,fetched_jses,len(saved.list)), end="\033[K\r")
		sleep(1)

if __name__ == "__main__":
	main(*sys.argv[1:])
