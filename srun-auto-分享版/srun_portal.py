#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
深澜（srun）校园网自动认证守护程序（通用版 / 分享版）

功能
  1. 掉线即重登：默认每 25 秒探测一次，连续 3 次失败判定掉线并立刻重新认证
  2. 定时检查：默认每天 06:00 与 15:30 各检查一次（电脑关机/休眠错过的会在开机后补跑）
  3. 失败退避：5s -> 15s -> 60s -> 300s，避免高频失败触发学校风控
  4. 本地网页图形界面：配置学号密码、查看实时日志、手动检查/登录
  5. 默认【不做主动退登】（用户要求）；如需"退出登录+重登"，把
     config.json 里的 enable_active_logout 改成 true 即可

协议细节均由抓包逆向并逐字节验证：
  hmd5   = HMAC-MD5(key=challenge, msg=password)
  info   = '{SRBX1}' + 自定义字母表base64( XEncode(JSON, challenge) )
  chksum = SHA1(challenge+username + challenge+hmd5 + challenge+ac_id + challenge+ip
                + challenge+n + challenge+type + challenge+info)
  自定义 base64 字母表：LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA

仅使用 Python 标准库，无需 pip 安装任何东西。
"""

import base64
import hashlib
import hmac
import json
import os
import random
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque

VERSION = '1.0.0'
HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, 'config.json')
LOG_DIR = os.path.join(HERE, 'logs')

UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
      'Chrome/155.0.0.0 Safari/537.36 Edg/155.0.0.0')

DEFAULT_CONFIG = {
    'username': '',
    'password': '',
    'portal_host': '',
    'ac_id': '1',
    'theme': 'pro',
    'os_name': 'Windows 10',
    'device_name': 'Windows',
    'check_interval_seconds': 25,
    'fail_threshold': 3,
    'fast_retry_seconds': 3,
    'internet_probe_url': 'http://connect.rom.miui.com/generate_204',
    'probe_timeout_seconds': 6,
    'daily_check_times': ['06:00', '15:30'],
    'catch_up_window_minutes': 120,
    'enable_active_logout': False,
    'retry_backoff_seconds': [5, 15, 60, 300],
    'web_bind': '127.0.0.1',
    'web_port': 8787,
    'log_max_bytes': 1048576,
    'log_keep_files': 3,
    'verbose_console': True,
}

M32 = 0xFFFFFFFF
DELTA = 0x86014019 | 0x183639A0
ALPHA = 'LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA'
STD_B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'


# --------------------------------------------------------------------------
# 加密部分（与 Portal.js 逐位一致）
# --------------------------------------------------------------------------
def _b64_quirk_encode(raw: bytes) -> str:
    std = base64.b64encode(raw).decode('ascii')
    tbl = {STD_B64[i]: ALPHA[i] for i in range(64)}
    return ''.join(tbl.get(c, c) for c in std)


def _b64_quirk_decode(text: str) -> bytes:
    text = text.rstrip('=')
    tbl = {ALPHA[i]: STD_B64[i] for i in range(64)}
    std = ''.join(tbl[c] for c in text)
    return base64.b64decode(std + '=' * (-len(std) % 4))


def _to_words(s: str, append_len: bool):
    n = len(s)
    words = []
    for i in range(0, n, 4):
        w = 0
        for j, ch in enumerate(s[i:i + 4]):
            w |= ord(ch) << (8 * j)
        words.append(w & M32)
    if append_len:
        words.append(n & M32)
    return words


def _from_words(words, use_len: bool):
    d = len(words)
    cap = (d - 1) << 2
    if use_len:
        m = words[d - 1]
        if m < cap - 3 or m > cap:
            return None
        cap = m
    out = ''.join(chr(w & 0xff) + chr((w >> 8) & 0xff) + chr((w >> 16) & 0xff)
                  + chr((w >> 24) & 0xff) for w in words)
    return out[:cap] if use_len else out


def _mix(z, y, d, kk):
    return (((z >> 5) ^ ((y << 2) & M32)) + (((y >> 3) ^ ((z << 4) & M32)) ^ (d ^ y))
            + (kk ^ z)) & M32


def xencode(msg: str, key: str) -> str:
    if msg == '':
        return ''
    v = _to_words(msg, True)
    k = _to_words(key, False)
    if len(k) < 4:
        k = k + [0] * (4 - len(k))
    n = len(v) - 1
    z, y = v[n], v[0]
    q = 6 + 52 // (n + 1)
    d = 0
    while q > 0:
        q -= 1
        d = (d + DELTA) & M32
        e = (d >> 2) & 3
        for p in range(n):
            y = v[p + 1]
            m = _mix(z, y, d, k[(p & 3) ^ e])
            z = v[p] = (v[p] + m) & M32
        y = v[0]
        m = _mix(z, y, d, k[(n & 3) ^ e])
        z = v[n] = (v[n] + m) & M32
    return _from_words(v, False)


def xdecode(msg: str, key: str):
    if msg == '':
        return ''
    v = _to_words(msg, False)
    k = _to_words(key, False)
    if len(k) < 4:
        k = k + [0] * (4 - len(k))
    n = len(v) - 1
    q = 6 + 52 // (n + 1)
    d = (q * DELTA) & M32
    while d != 0:
        e = (d >> 2) & 3
        m = _mix(v[n - 1], v[0], d, k[(n & 3) ^ e])
        v[n] = (v[n] - m) & M32
        for p in range(n - 1, -1, -1):
            z = v[n] if p == 0 else v[p - 1]
            m = _mix(z, v[p + 1], d, k[(p & 3) ^ e])
            v[p] = (v[p] - m) & M32
        d = (d - DELTA) & M32
    return _from_words(v, True)


def hmd5(password: str, token: str) -> str:
    """Portal.js 里的 md5(password, token) —— 实为 HMAC-MD5。"""
    return hmac.new(token.encode('utf-8'), password.encode('utf-8'), hashlib.md5).hexdigest()


def sha1_hex(text: str) -> str:
    return hashlib.sha1(text.encode('utf-8')).hexdigest()


# --------------------------------------------------------------------------
# 日志
# --------------------------------------------------------------------------
class Logger:
    def __init__(self, directory, max_bytes, keep_files, echo=True):
        os.makedirs(directory, exist_ok=True)
        self.path = os.path.join(directory, 'srun-%s.log' % time.strftime('%Y%m%d'))
        self.max_bytes = int(max_bytes)
        self.keep = int(keep_files)
        self.echo = echo
        self.ring = deque(maxlen=400)
        self.lock = threading.Lock()
        self._rotate_if_needed()

    def _rotate_if_needed(self):
        try:
            if os.path.exists(self.path) and os.path.getsize(self.path) > self.max_bytes:
                for i in range(self.keep, 0, -1):
                    src = '%s.%d' % (self.path, i)
                    dst = '%s.%d' % (self.path, i + 1)
                    if os.path.exists(src):
                        if i == self.keep:
                            os.remove(src)
                        else:
                            os.replace(src, dst)
                os.replace(self.path, self.path + '.1')
        except OSError:
            pass

    def __call__(self, msg):
        line = '[%s] %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), msg)
        with self.lock:
            self.ring.append(line)
            try:
                self._rotate_if_needed()
                with open(self.path, 'a', encoding='utf-8') as f:
                    f.write(line + '\n')
            except OSError:
                pass
        if self.echo:
            try:
                print(line, flush=True)
            except Exception:
                pass

    def tail(self, n=200):
        with self.lock:
            return list(self.ring)[-n:]


# --------------------------------------------------------------------------
# 配置
# --------------------------------------------------------------------------
def load_config(path=CONFIG_PATH):
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                cfg.update(json.load(f))
        except Exception as e:
            print('配置文件读取失败，使用默认值：%s' % e)
    return cfg


def save_config(cfg, path=CONFIG_PATH):
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


# --------------------------------------------------------------------------
# 深澜客户端
# --------------------------------------------------------------------------
class SrunClient:
    def __init__(self, cfg, log):
        self.cfg = cfg
        self.log = log
        self.last_client_ip = None

    # ---- 基础 HTTP ----
    def _get(self, url, timeout=None):
        timeout = timeout or float(self.cfg['probe_timeout_seconds'])
        req = urllib.request.Request(url, headers={
            'User-Agent': UA,
            'Accept': 'text/javascript, application/javascript, application/ecmascript, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'X-Requested-With': 'XMLHttpRequest',
            'Referer': 'http://%s/srun_portal_pc?ac_id=%s&theme=%s'
                       % (self.cfg['portal_host'], self.cfg['ac_id'], self.cfg['theme']),
        })
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode('utf-8', 'replace')

    def _portal(self):
        return 'http://%s' % self.cfg['portal_host']

    @staticmethod
    def _callback():
        return 'jQuery%d_%d' % (random.randint(10 ** 15, 10 ** 16), int(time.time() * 1000))

    @staticmethod
    def _jsonp(text):
        text = text.strip()
        m = re.search(r'^[^(]*\((.*)\)[;\s]*$', text, re.S)
        payload = m.group(1) if m else text
        return json.loads(payload)

    # ---- 取 challenge ----
    def challenge(self, ip=''):
        cb = self._callback()
        url = ('%s/cgi-bin/get_challenge?callback=%s&username=%s&ip=%s&_=%d'
               % (self._portal(), cb, urllib.parse.quote(self.cfg['username']),
                  urllib.parse.quote(ip), int(time.time() * 1000)))
        _, body = self._get(url)
        data = self._jsonp(body)
        if not data.get('challenge'):
            raise RuntimeError('获取 challenge 失败：%s' % body[:200])
        if data.get('client_ip'):
            self.last_client_ip = data['client_ip']
        return data

    # ---- 组装登录 URL（独立出来便于自检）----
    def build_login_url(self, token, password, ip, callback, ts):
        username = self.cfg['username']
        ac_id = str(self.cfg['ac_id'])
        n, typ = 200, 1
        enc_ver = 'srun_bx1'

        info_json = json.dumps({
            'username': username,
            'password': password,
            'ip': ip,
            'acid': ac_id,
            'enc_ver': enc_ver,
        }, separators=(',', ':'), ensure_ascii=False)

        pw_hash = hmd5(password, token)
        info = '{SRBX1}' + _b64_quirk_encode(xencode(info_json, token).encode('latin-1'))

        parts = token + username
        parts += token + pw_hash
        parts += token + ac_id
        parts += token + ip
        parts += token + str(n)
        parts += token + str(typ)
        parts += token + info

        params = [
            ('callback', callback),
            ('action', 'login'),
            ('username', username),
            ('password', '{MD5}' + pw_hash),
            ('os', self.cfg['os_name']),
            ('name', self.cfg['device_name']),
            ('double_stack', '0'),
            ('chksum', sha1_hex(parts)),
            ('info', info),
            ('ac_id', ac_id),
            ('ip', ip),
            ('n', str(n)),
            ('type', str(typ)),
            ('_', str(ts)),
        ]
        return '%s/cgi-bin/srun_portal?%s' % (self._portal(), urllib.parse.urlencode(params))

    # ---- 登录 ----
    def login(self):
        password = self.cfg.get('password') or ''
        if not password:
            raise RuntimeError('还没有配置密码，请在网页界面里填写')

        ch = self.challenge('')
        token = ch['challenge']
        ip = ch.get('client_ip') or self.last_client_ip or ''
        if not ip:
            raise RuntimeError('拿不到出口 IP，无法认证')

        cb = self._callback()
        url = self.build_login_url(token, password, ip, cb, int(time.time() * 1000))
        _, body = self._get(url)
        data = self._jsonp(body)

        err = str(data.get('error') or '')
        emsg = str(data.get('error_msg') or '')
        suc = str(data.get('suc_msg') or '')
        ok = (err == 'ok') or (str(data.get('res') or '') == 'ok') or (suc == 'login_ok') \
            or ('ip_already_online_error' in err) or ('ip_already_online_error' in emsg)
        return {
            'ok': ok,
            'ip': ip,
            'error': err,
            'error_msg': emsg,
            'suc_msg': suc,
            'ploy_msg': data.get('ploy_msg', ''),
            'ecode': data.get('ecode'),
            'raw': data,
        }

    # ---- 在线状态（校园网自己的口径）----
    def status(self):
        cb = self._callback()
        url = ('%s/cgi-bin/rad_user_info?callback=%s&_=%d'
               % (self._portal(), cb, int(time.time() * 1000)))
        _, body = self._get(url)
        data = self._jsonp(body)
        err = str(data.get('error') or data.get('res') or '')
        online = (err == 'ok') and bool(data.get('user_name') or data.get('online_ip'))
        return {'online': online, 'error': err, 'data': data}

    # ---- 注销（默认不启用）----
    def logout(self):
        ch = self.challenge('')
        ip = ch.get('client_ip') or self.last_client_ip or ''
        now = int(time.time())
        sign = sha1_hex('%d%s%s%d%d' % (now, self.cfg['username'], ip, 1, now))
        cb = self._callback()
        params = [
            ('callback', cb),
            ('ip', ip),
            ('username', self.cfg['username']),
            ('time', str(now)),
            ('unbind', '1'),
            ('sign', sign),
            ('_', str(int(time.time() * 1000))),
        ]
        url = '%s/cgi-bin/rad_user_dm?%s' % (self._portal(), urllib.parse.urlencode(params))
        _, body = self._get(url)
        data = self._jsonp(body)
        return {'ok': str(data.get('error') or '') == 'ok', 'raw': data}

    # ---- 真实上网通路 ----
    def internet_ok(self):
        url = self.cfg['internet_probe_url']
        req = urllib.request.Request(url, headers={'User-Agent': UA})
        try:
            with urllib.request.urlopen(req, timeout=float(self.cfg['probe_timeout_seconds'])) as r:
                return r.status == 204, 'HTTP %d' % r.status
        except urllib.error.HTTPError as e:
            return False, 'HTTP %d' % e.code
        except Exception as e:
            return False, type(e).__name__


# --------------------------------------------------------------------------
# 调度 + 状态
# --------------------------------------------------------------------------
def hhmm_to_minutes(text):
    h, m = text.strip().split(':')
    return int(h) * 60 + int(m)


class Monitor(threading.Thread):
    def __init__(self, cfg, client, log):
        super().__init__(daemon=True)
        self.cfg = cfg
        self.client = client
        self.log = log
        self.stop_flag = threading.Event()
        self.wake = threading.Event()
        self.lock = threading.Lock()
        self.state = {
            'started_at': time.time(),
            'online': None,
            'last_check': None,
            'last_check_reason': '',
            'last_ok': None,
            'last_error': '',
            'client_ip': '',
            'fails': 0,
            'login_count': 0,
            'today': time.strftime('%Y-%m-%d'),
            'today_logins': 0,
            'last_login': None,
            'next_probe': None,
            'last_probe_detail': '',
        }
        self.slots = []
        self._rebuild_slots()

    def _rebuild_slots(self):
        old = {s['text']: s['last_day'] for s in (self.slots or [])}
        self.slots = []
        for t in self.cfg.get('daily_check_times') or []:
            try:
                self.slots.append({'text': t, 'minutes': hhmm_to_minutes(t), 'last_day': old.get(t)})
            except Exception:
                self.log('忽略无法解析的定时时间：%r' % t)

    def reload(self):
        self._rebuild_slots()

    def snapshot(self):
        with self.lock:
            s = dict(self.state)
        s['version'] = VERSION
        s['running'] = not self.stop_flag.is_set()
        s['config'] = {k: v for k, v in self.cfg.items() if k != 'password'}
        s['has_password'] = bool(self.cfg.get('password'))
        s['daily_check_times'] = list(self.cfg.get('daily_check_times') or [])
        return s

    def _update(self, **kw):
        with self.lock:
            self.state.update(kw)

    def request_check(self, reason='手动'):
        self._pending_reason = reason
        self.wake.set()

    # ---- 一次探测 ----
    def check_once(self, reason, allow_login=True):
        ok_inet, detail = self.client.internet_ok()
        ip = self.client.last_client_ip or ''
        if ok_inet:
            if not ip:   # 顺便补上出口 IP，方便界面显示与排查
                try:
                    st = self.client.status()
                    ip = st['data'].get('online_ip') or self.client.last_client_ip or ''
                except Exception:
                    pass
            self._update(online=True, last_check=time.time(), last_ok=time.time(),
                         last_check_reason=reason, fails=0, client_ip=ip,
                         last_probe_detail=detail, last_error='')
            self.log('检查[%s]：在线（%s，出口 %s）' % (reason, detail, ip or '未知'))
            return True

        # 网络不通 —— 看看是不是认证掉了
        try:
            st = self.client.status()
        except Exception as e:
            self._bump_fails()
            self._update(last_check=time.time(), last_check_reason=reason,
                         last_probe_detail='%s / 状态查询失败 %s' % (detail, type(e).__name__))
            self.log('检查[%s]：上网不通（%s），而且查不到认证状态（%s）'
                     % (reason, detail, type(e).__name__))
            return False

        if st['online']:
            self._bump_fails()
            self._update(online=True, last_check=time.time(), last_ok=time.time(),
                         client_ip=st['data'].get('online_ip', ip) or ip,
                         last_check_reason=reason, last_probe_detail=detail,
                         last_error='校园网侧显示在线，但上网不通（可能是上游故障）')
            self.log('检查[%s]：校园网侧显示在线，但上网不通（%s），先不重登' % (reason, detail))
            return False

        self.log('检查[%s]：已被下线（%s），开始重新认证' % (reason, detail))
        if allow_login:
            self.do_login(reason)
        else:
            self._bump_fails()
        return False

    def _bump_fails(self):
        with self.lock:
            self.state['fails'] = int(self.state.get('fails') or 0) + 1
            return self.state['fails']

    def do_login(self, reason=''):
        backoff = list(self.cfg.get('retry_backoff_seconds') or [5, 15, 60, 300])
        attempt = 0
        while not self.stop_flag.is_set():
            attempt += 1
            try:
                res = self.client.login()
            except Exception as e:
                res = {'ok': False, 'error': type(e).__name__, 'error_msg': str(e), 'ip': ''}
            if res.get('ok'):
                now = time.time()
                today = time.strftime('%Y-%m-%d')
                with self.lock:
                    if self.state['today'] != today:
                        self.state['today'] = today
                        self.state['today_logins'] = 0
                    self.state['today_logins'] += 1
                    self.state['login_count'] += 1
                    self.state['last_login'] = now
                    self.state['online'] = True
                    self.state['last_ok'] = now
                    self.state['fails'] = 0
                    self.state['client_ip'] = res.get('ip') or self.state['client_ip']
                    self.state['last_error'] = ''
                self.log('登录成功（第 %d 次尝试，出口 %s，%s）'
                         % (attempt, res.get('ip') or '?', res.get('suc_msg') or res.get('ploy_msg') or 'ok'))
                return True
            msg = '%s %s' % (res.get('error'), res.get('error_msg') or '')
            self._update(last_error=msg.strip(), online=False)
            delay = backoff[min(attempt - 1, len(backoff) - 1)]
            self.log('登录失败（第 %d 次）：%s —— %d 秒后重试' % (attempt, msg.strip(), delay))
            if self.stop_flag.wait(delay):
                return False
        return False

    # ---- 主循环 ----
    def run(self):
        self.log('守护程序已启动（v%s），探测间隔 %ss，定时检查 %s'
                 % (VERSION, self.cfg.get('check_interval_seconds'),
                    ','.join(self.cfg.get('daily_check_times') or []) or '无'))
        if not self.cfg.get('portal_host'):
            self.log('提示：还没填认证服务器地址（校园网认证页的地址，通常是 10.x.x.x），'
                     '请在网页界面「认证服务器」里填写后保存')
        if not self.cfg.get('password'):
            self.log('提示：还没填密码，请打开网页界面填写后保存')
        next_probe = 0.0
        while not self.stop_flag.is_set():
            try:
                next_probe = self._tick(next_probe)
            except Exception:
                import traceback
                self.log('探测循环出现异常（已忽略并继续运行）：%s'
                         % traceback.format_exc().replace('\n', ' | '))
                time.sleep(5)
        self.log('守护线程已退出')

    def _tick(self, next_probe):
        now = time.time()
        today = time.strftime('%Y-%m-%d')
        now_min = time.localtime(now).tm_hour * 60 + time.localtime(now).tm_min

        # 定时检查（含关机/休眠错过后的补跑）
        for slot in self.slots:
            if now_min >= slot['minutes'] and slot['last_day'] != today:
                slot['last_day'] = today
                late = now_min - slot['minutes']
                if late <= int(self.cfg.get('catch_up_window_minutes', 120)):
                    self._scheduled(slot['text'])
                else:
                    self.log('已错过定时检查点 %s（晚了 %d 分钟，超过补跑窗口），跳过'
                             % (slot['text'], late))

        if self.wake.is_set():
            self.wake.clear()
            reason = getattr(self, '_pending_reason', '手动')
            self.check_once(reason)
            self._update(next_probe=time.time() + float(self.cfg['check_interval_seconds']))
            return time.time() + float(self.cfg['check_interval_seconds'])

        if now >= next_probe:
            if self.cfg.get('password') and self.cfg.get('portal_host'):
                online = self.check_once('定时探测')
                if online:
                    next_probe = time.time() + float(self.cfg['check_interval_seconds'])
                else:
                    with self.lock:
                        fails = self.state['fails']
                    next_probe = time.time() + (float(self.cfg['fast_retry_seconds'])
                                                if fails < int(self.cfg['fail_threshold']) else 10)
            else:
                _why = ('未配置密码' if not self.cfg.get('password')
                        else '未配置认证服务器地址')
                self._update(online=None, last_check=time.time(), last_check_reason=_why)
                next_probe = time.time() + 30
            self._update(next_probe=next_probe)
        time.sleep(1)
        return next_probe

    def _scheduled(self, text):
        self.log('到达定时检查点 %s' % text)
        if self.cfg.get('enable_active_logout'):
            self.log('已启用主动退登：先退出登录再重新认证')
            try:
                self.client.logout()
            except Exception as e:
                self.log('退出登录失败（忽略，继续重登）：%s' % e)
            self.do_login('定时退登重登 %s' % text)
        else:
            if self.cfg.get('password') and self.cfg.get('portal_host'):
                self.check_once('定时检查 %s' % text)
            else:
                self.log('还没配置好账号或认证服务器地址，跳过定时检查')


# --------------------------------------------------------------------------
# 网页图形界面
# --------------------------------------------------------------------------
PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>校园网自动认证 · 控制台</title>
<style>
 :root{--bg:#0f1216;--card:#171c22;--line:#252c35;--fg:#e6ebf2;--dim:#8b98a8;
       --ok:#2ecc71;--bad:#ff5d5d;--warn:#f5a623;--acc:#3b82f6}
 *{box-sizing:border-box}
 body{margin:0;background:var(--bg);color:var(--fg);
      font:14px/1.6 "Microsoft YaHei",system-ui,-apple-system,Segoe UI,sans-serif}
 .wrap{max-width:960px;margin:0 auto;padding:20px}
 h1{font-size:19px;margin:0 0 4px}
 .sub{color:var(--dim);font-size:12px;margin-bottom:18px}
 .card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:14px}
 .row{display:flex;flex-wrap:wrap;gap:12px}
 .col{flex:1 1 200px;min-width:150px}
 .k{color:var(--dim);font-size:12px}
 .v{font-size:15px;font-weight:600;word-break:break-all}
 .badge{display:inline-block;padding:3px 10px;border-radius:99px;font-size:12px;font-weight:700}
 .b-ok{background:rgba(46,204,113,.15);color:var(--ok);border:1px solid rgba(46,204,113,.4)}
 .b-bad{background:rgba(255,93,93,.15);color:var(--bad);border:1px solid rgba(255,93,93,.4)}
 .b-warn{background:rgba(245,166,35,.15);color:var(--warn);border:1px solid rgba(245,166,35,.4)}
 label{display:block;font-size:12px;color:var(--dim);margin:10px 0 4px}
 input[type=text],input[type=password],input[type=number]{width:100%;padding:8px 10px;border-radius:7px;
      border:1px solid var(--line);background:#0d1116;color:var(--fg);font-size:13px}
 button{padding:8px 14px;border-radius:7px;border:1px solid var(--line);background:#1e252e;
      color:var(--fg);cursor:pointer;font-size:13px}
 button:hover{background:#26303b}
 button.primary{background:var(--acc);border-color:var(--acc);color:#fff}
 button.primary:hover{background:#2f6fd8}
 .btns{display:flex;flex-wrap:wrap;gap:8px;margin-top:14px}
 pre{background:#0b0e12;border:1px solid var(--line);border-radius:8px;padding:12px;height:260px;
      overflow:auto;font:12px/1.5 Consolas,monospace;white-space:pre-wrap;word-break:break-all;margin:0}
 .toast{position:fixed;right:18px;bottom:18px;background:#1e252e;border:1px solid var(--line);
      padding:10px 14px;border-radius:8px;opacity:0;transition:.25s;pointer-events:none}
 .toast.on{opacity:1}
 .switch{display:flex;align-items:center;gap:8px;margin-top:12px;color:var(--dim);font-size:12px}
</style>
</head>
<body>
<div class="wrap">
  <h1>校园网自动认证 · 控制台</h1>
  <div class="sub">深澜 srun 校园网 · <span id="ver"></span></div>

  <div class="card">
    <div class="row">
      <div class="col"><div class="k">当前状态</div><div class="v" id="st-online">未知</div></div>
      <div class="col"><div class="k">出口 IP</div><div class="v" id="st-ip">-</div></div>
      <div class="col"><div class="k">最后检查</div><div class="v" id="st-last">-</div></div>
      <div class="col"><div class="k">今日登录</div><div class="v" id="st-count">0</div></div>
      <div class="col"><div class="k">连续失败</div><div class="v" id="st-fails">0</div></div>
      <div class="col"><div class="k">运行时长</div><div class="v" id="st-up">-</div></div>
    </div>
    <div class="btns">
      <button class="primary" onclick="act('check')">立即检查</button>
      <button onclick="act('login')">立即登录</button>
      <button onclick="act('logout')">退出登录（测试用）</button>
      <button onclick="location.reload()">刷新页面</button>
    </div>
    <div class="k" style="margin-top:10px" id="st-detail"></div>
  </div>

  <div class="card">
    <div class="k" style="font-size:13px;color:#e6ebf2;font-weight:600">账号设置</div>
    <div class="row">
      <div class="col"><label>学号 / 用户名</label><input type="text" id="c-username"></div>
      <div class="col"><label>密码</label><input type="password" id="c-password" placeholder="留空表示不修改"></div>
    </div>
    <div class="row">
      <div class="col"><label>认证服务器</label><input type="text" id="c-portal_host"></div>
      <div class="col"><label>ac_id</label><input type="text" id="c-ac_id"></div>
      <div class="col"><label>theme</label><input type="text" id="c-theme"></div>
    </div>
    <div class="row">
      <div class="col"><label>探测间隔（秒）</label><input type="number" id="c-check_interval_seconds"></div>
      <div class="col"><label>连续失败几次判定掉线</label><input type="number" id="c-fail_threshold"></div>
      <div class="col"><label>定时检查时间（逗号分隔）</label><input type="text" id="c-daily_check_times"></div>
    </div>
    <div class="row">
      <div class="col"><label>上网探测地址</label><input type="text" id="c-internet_probe_url"></div>
    </div>
    <div class="switch">
      <input type="checkbox" id="c-enable_active_logout">
      <label for="c-enable_active_logout" style="margin:0">
        启用「主动退登 + 重登」（默认关闭；打开后每次定时检查会先退出登录再重新认证）</label>
    </div>
    <div class="btns"><button class="primary" onclick="saveCfg()">保存设置</button></div>
  </div>

  <div class="card">
    <div class="k" style="font-size:13px;color:#e6ebf2;font-weight:600;margin-bottom:8px">运行日志</div>
    <pre id="log">加载中…</pre>
  </div>
</div>
<div class="toast" id="toast"></div>

<script>
const CFG_KEYS = ['username','portal_host','ac_id','theme','check_interval_seconds',
                  'fail_threshold','internet_probe_url','enable_active_logout'];
function toast(msg){const t=document.getElementById('toast');t.textContent=msg;t.classList.add('on');
  clearTimeout(t._h);t._h=setTimeout(()=>t.classList.remove('on'),2200);}
function fmt(ts){if(!ts)return '-';const d=new Date(ts*1000);const p=n=>String(n).padStart(2,'0');
  return p(d.getMonth()+1)+'-'+p(d.getDate())+' '+p(d.getHours())+':'+p(d.getMinutes())+':'+p(d.getSeconds());}
async function refresh(){
  try{
    const s = await (await fetch('/api/status')).json();
    document.getElementById('ver').textContent = 'v'+s.version+(s.running?' · 运行中':' · 已停止');
    const el = document.getElementById('st-online');
    if(s.online===true){el.innerHTML='<span class="badge b-ok">在线</span>';}
    else if(s.online===false){el.innerHTML='<span class="badge b-bad">掉线</span>';}
    else {el.innerHTML='<span class="badge b-warn">未检测</span>';}
    document.getElementById('st-ip').textContent = s.client_ip||'-';
    document.getElementById('st-last').textContent = fmt(s.last_check);
    document.getElementById('st-count').textContent = s.today_logins;
    document.getElementById('st-fails').textContent = s.fails;
    const up = s.started_at? Math.floor(Date.now()/1000-s.started_at):0;
    document.getElementById('st-up').textContent = Math.floor(up/3600)+' 小时 '+Math.floor(up%3600/60)+' 分';
    let d = '最近一次：'+(s.last_check_reason||'-');
    if(s.last_probe_detail) d += ' · '+s.last_probe_detail;
    if(s.last_error) d += ' · 最近错误：'+s.last_error;
    d += ' · 定时检查：'+(s.daily_check_times||[]).join(' / ');
    document.getElementById('st-detail').textContent = d;
    const cfg = s.config||{};
    for(const k of CFG_KEYS){
      const e = document.getElementById('c-'+k);
      if(!e) continue;
      if(k==='enable_active_logout') e.checked = !!cfg[k];
      else if(k==='daily_check_times') e.value = (s.daily_check_times||[]).join(',');
      else if(document.activeElement!==e) e.value = cfg[k]===undefined?'':cfg[k];
    }
  }catch(e){ }
  try{ document.getElementById('log').textContent = await (await fetch('/api/log')).text(); }catch(e){}
}
async function saveCfg(){
  const body = {};
  for(const k of CFG_KEYS){
    const e = document.getElementById('c-'+k); if(!e) continue;
    if(k==='enable_active_logout') body[k]=e.checked;
    else if(k==='daily_check_times') body[k]=e.value.split(',').map(x=>x.trim()).filter(Boolean);
    else if(k==='check_interval_seconds'||k==='fail_threshold') body[k]=Number(e.value);
    else body[k]=e.value.trim();
  }
  const pw = document.getElementById('c-password').value;
  if(pw) body.password = pw;
  const r = await fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify(body)});
  const j = await r.json();
  toast(j.ok? '已保存'+(j.note?('（'+j.note+'）'):'') : ('保存失败：'+(j.error||'')));
  document.getElementById('c-password').value='';
  refresh();
}
async function act(a){
  toast('已发送：'+a);
  const r = await fetch('/api/action',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({action:a})});
  const j = await r.json(); if(!j.ok) toast('失败：'+(j.error||''));
  setTimeout(refresh,600);
}
refresh(); setInterval(refresh, 3000);
</script>
</body>
</html>
"""


def make_handler(monitor, client, cfg, log):
    from http.server import BaseHTTPRequestHandler

    class Handler(BaseHTTPRequestHandler):
        server_version = 'srun-portal/%s' % VERSION

        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype='application/json; charset=utf-8'):
            if isinstance(body, str):
                body = body.encode('utf-8')
            self.send_response(code)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            try:
                self.wfile.write(body)
            except Exception:
                pass

        def _json(self, obj, code=200):
            self._send(code, json.dumps(obj, ensure_ascii=False))

        def _body(self):
            n = int(self.headers.get('Content-Length') or 0)
            raw = self.rfile.read(n) if n else b'{}'
            try:
                return json.loads(raw.decode('utf-8'))
            except Exception:
                return {}

        def do_GET(self):
            path = urllib.parse.urlparse(self.path).path
            if path in ('/', '/index.html'):
                return self._send(200, PAGE, 'text/html; charset=utf-8')
            if path == '/api/status':
                return self._json(monitor.snapshot())
            if path == '/api/log':
                return self._send(200, '\n'.join(log.tail(300)), 'text/plain; charset=utf-8')
            return self._send(404, 'not found', 'text/plain; charset=utf-8')

        def do_POST(self):
            path = urllib.parse.urlparse(self.path).path
            data = self._body()
            if path == '/api/config':
                try:
                    for k, v in data.items():
                        if k == 'password':
                            cfg['password'] = v
                        elif k in DEFAULT_CONFIG:
                            cfg[k] = v
                    save_config(cfg)
                    monitor.reload()
                    log('配置已更新（密码%s）' % ('已设置' if cfg.get('password') else '为空'))
                    note = '密码已设置' if cfg.get('password') else '密码为空'
                    return self._json({'ok': True, 'note': note})
                except Exception as e:
                    return self._json({'ok': False, 'error': str(e)}, 500)
            if path == '/api/action':
                a = (data.get('action') or '').strip()
                if a == 'check':
                    monitor.request_check('手动检查')
                    return self._json({'ok': True})
                if a == 'login':
                    threading.Thread(target=monitor.do_login, kwargs={'reason': '手动'},
                                     daemon=True).start()
                    return self._json({'ok': True})
                if a == 'logout':
                    try:
                        r = client.logout()
                        log('手动退出登录：%s' % ('成功' if r['ok'] else r['raw']))
                        return self._json({'ok': r['ok'], 'raw': r['raw']})
                    except Exception as e:
                        return self._json({'ok': False, 'error': str(e)}, 500)
                return self._json({'ok': False, 'error': '未知操作'}, 400)
            return self._json({'ok': False, 'error': 'not found'}, 404)

    return Handler


def run_gui(monitor, client, cfg, log):
    import socket
    from http.server import ThreadingHTTPServer
    bind = cfg.get('web_bind', '127.0.0.1')
    port = int(cfg.get('web_port', 8787))

    # 单实例保护：Windows 上 SO_REUSEADDR 允许重复绑定同一端口，所以先主动探测一次
    probe = socket.socket()
    probe.settimeout(1.0)
    try:
        probe.connect(('127.0.0.1' if bind in ('0.0.0.0', '', '::') else bind, port))
        probe.close()
        log('端口 %s:%d 已经被占用：很可能已经有一个实例在运行。' % (bind, port))
        return None
    except Exception:
        try:
            probe.close()
        except Exception:
            pass

    class Server(ThreadingHTTPServer):
        allow_reuse_address = False
        daemon_threads = True

    handler = make_handler(monitor, client, cfg, log)
    try:
        httpd = Server((bind, port), handler)
    except OSError as e:
        log('网页界面启动失败（%s:%s）：%s' % (bind, port, e))
        return None
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    log('网页界面已启动：http://%s:%d/' % (bind, port))
    return httpd


# --------------------------------------------------------------------------
# 离线自检：用抓包数据逐字节复现登录请求
# --------------------------------------------------------------------------
SELFTEST = {
    # 分享版已移除原作者的抓包验证数据：原数据含账号，而且 info 密文配合 token 可以逆推出明文密码。
    # 想保留离线自检能力，请填入自己的抓包数据：
    #   token       —— get_challenge 响应里的 challenge
    #   ip          —— 当时的出口 IP
    #   expect      —— 浏览器实际发出的 /cgi-bin/srun_portal?... 完整地址
    #   expect_hmd5 —— 该地址里 password={MD5} 后面的那串
    'token': '',
    'ip': '',
    'callback': '',
    'ts': 0,
    'expect_hmd5': '',
    'expect': '',
}


def selftest(cfg):
    """用抓包数据逐字节复现登录请求，确认协议实现正确。"""
    if not SELFTEST.get('token') or not SELFTEST.get('expect'):
        print('分享版没有内置验证向量，跳过离线自检。')
        print('（加密实现本身没有被改动；要自检请把抓包数据填进 srun_portal.py 的 SELFTEST。）')
        return 0
    password = cfg.get('password') or ''
    if not password:
        print('config.json 里还没有密码，无法做自检。')
        return 1
    if hmd5(password, SELFTEST['token']) != SELFTEST['expect_hmd5']:
        print('config.json 中的密码与抓包验证向量不是同一个，跳过逐字节自检。')
        print('（这只说明密码不同，不代表协议实现有问题；实际登录仍会使用你配置的密码。）')
        return 0

    client = SrunClient(cfg, Logger(LOG_DIR, 10 ** 7, 1, echo=False))
    got = client.build_login_url(SELFTEST['token'], password, SELFTEST['ip'],
                                 SELFTEST['callback'], SELFTEST['ts'])
    print('自检：与抓包结果逐字节对比')
    print('  期望长度 %d / 实际长度 %d' % (len(SELFTEST['expect']), len(got)))
    if got == SELFTEST['expect']:
        print('  OK 完全一致，协议实现正确')
        return 0
    print('  不一致')
    for i, (a, b) in enumerate(zip(SELFTEST['expect'], got)):
        if a != b:
            print('    首个差异在第 %d 字节：期望 %r 实际 %r' % (i, a, b))
            print('    期望片段:', SELFTEST['expect'][max(0, i - 60):i + 60])
            print('    实际片段:', got[max(0, i - 60):i + 60])
            break
    return 1


# --------------------------------------------------------------------------
# 入口
# --------------------------------------------------------------------------
def main(argv):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

    args = [a for a in argv[1:]]

    cfg = load_config()
    if '--selftest' in args:
        return selftest(cfg)
    for a in args:
        if a.startswith('--set='):
            k, _, v = a[6:].partition('=')
            if k in DEFAULT_CONFIG:
                cfg[k] = v
    log = Logger(LOG_DIR, cfg['log_max_bytes'], cfg['log_keep_files'],
                 echo=bool(cfg.get('verbose_console')))
    client = SrunClient(cfg, log)
    monitor = Monitor(cfg, client, log)

    if '--check' in args:
        ok = monitor.check_once('命令行')
        print(json.dumps(monitor.snapshot(), ensure_ascii=False, indent=2))
        return 0 if ok else 2
    if '--login' in args:
        if not cfg.get('portal_host') or not cfg.get('password'):
            print('还没配置认证服务器地址或密码，请先在控制台（或 config.json）里填写。')
            return 2
        return 0 if monitor.do_login('命令行') else 1
    if '--status' in args:
        if not cfg.get('portal_host'):
            print('还没配置认证服务器地址（config.json 的 portal_host，或控制台里的「认证服务器」）。')
            return 2
        st = client.status()
        print(json.dumps(st['data'], ensure_ascii=False, indent=2))
        return 0 if st['online'] else 2

    if '--no-gui' in args:
        httpd = None
    else:
        httpd = run_gui(monitor, client, cfg, log)
        if httpd is None:
            log('端口 %s 已被占用：很可能已经有一个实例在运行，本次不再重复启动。'
                % cfg.get('web_port'))
            log('如果你确定那是别的程序占用该端口，请改 config.json 里的 web_port 再启动。')
            return 3
    monitor.start()
    log('提示：关闭这个窗口程序就停止了；要后台常驻请看 README（开机自启）')
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        log('收到退出信号，正在停止…')
        monitor.stop_flag.set()
        if httpd:
            httpd.shutdown()
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
