# app.py
import os
import logging
import socket
import time
import json
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from apscheduler.schedulers.background import BackgroundScheduler
from pythonping import ping
import smtplib
from email.mime.text import MIMEText
import threading
import requests
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import io
import base64
import pandas as pd
from sqlalchemy import Index, or_
import warnings
from urllib3.exceptions import InsecureRequestWarning

# Suppress InsecureRequestWarning
warnings.simplefilter('ignore', InsecureRequestWarning)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key-change-in-prod'  # Required for sessions/flash; use env var in prod
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////app/db/monitor.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class IPAddress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(255))
    blacklist = db.Column(db.Boolean, default=False)
    pause_until = db.Column(db.DateTime(timezone=True))
    notifications_enabled = db.Column(db.Boolean, default=True)
    quiet_hours_enabled = db.Column(db.Boolean, default=False)
    last_alerted_fails = db.Column(db.Integer, default=0)
    monitor_type = db.Column(db.String(20), default='icmp')
    monitor_port = db.Column(db.Integer, default=None)
    monitor_url = db.Column(db.String(500), default=None)
    monitor_keyword = db.Column(db.String(255), default=None)
    interval_seconds = db.Column(db.Integer, default=20)
    alert_threshold = db.Column(db.Integer, default=None)
    resend_every = db.Column(db.Integer, default=None)  # Per-target override for resend_every
    quiet_start = db.Column(db.Integer, default=None)
    quiet_end = db.Column(db.Integer, default=None)

class PingLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_id = db.Column(db.Integer, db.ForeignKey('ip_address.id'))
    timestamp = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    success = db.Column(db.Boolean)
    latency = db.Column(db.Float)
    
    __table_args__ = (
        db.Index('idx_pinglog_ip_timestamp', 'ip_id', 'timestamp'),
    )

class Config(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email_host = db.Column(db.String(255), default='smtp.gmail.com')
    email_port = db.Column(db.Integer, default=587)
    email_user = db.Column(db.String(255))
    email_pass = db.Column(db.String(255))
    email_recipient = db.Column(db.String(255), default='')
    email_use_tls = db.Column(db.Boolean, default=True)
    email_use_ssl = db.Column(db.Boolean, default=False)
    email_enabled = db.Column(db.Boolean, default=True)
    discord_webhook = db.Column(db.String(500))
    discord_enabled = db.Column(db.Boolean, default=True)
    custom_webhook_url = db.Column(db.String(500))
    custom_webhook_enabled = db.Column(db.Boolean, default=True)
    alert_threshold = db.Column(db.Integer, default=2)
    resend_every = db.Column(db.Integer, default=20)
    quiet_hours_start = db.Column(db.Integer, default=22)
    quiet_hours_end = db.Column(db.Integer, default=6)

with app.app_context():
    db.create_all()
    c = Config.query.first()
    if not c:
        db.session.add(Config())
        db.session.commit()

LIVE = {}
lock = threading.Lock()
scheduler = BackgroundScheduler()
scheduler.start()

def normalize_to_utc(dt):
    """Normalize datetime to UTC: if naive, assume UTC; if aware, convert to UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    else:
        return dt.astimezone(timezone.utc)

def is_quiet_hours(config, ip_quiet_enabled, quiet_start=None, quiet_end=None):
    if not ip_quiet_enabled:
        return False
    now_hour = datetime.now(timezone.utc).hour
    start = quiet_start or config.quiet_hours_start
    end = quiet_end or config.quiet_hours_end
    if start < end:
        return start <= now_hour < end
    else:
        return now_hour >= start or now_hour < end

def send_notification(ip, status, lat=None, desc=None, consecutive=None, ip_quiet_enabled=False, quiet_start=None, quiet_end=None):
    with app.app_context():
        config = Config.query.first()
        logger.info(f"Attempting to send {status} notification for {ip} (consecutive: {consecutive})")
        if is_quiet_hours(config, ip_quiet_enabled, quiet_start, quiet_end):
            logger.info(f"Quiet hours active for {ip}: Skipping alert {status}")
            return

        ip_obj = IPAddress.query.filter_by(ip=ip).first()
        if not ip_obj:
            logger.error(f"IP object not found for {ip}")
            return
        if not ip_obj.notifications_enabled:
            logger.info(f"Notifications disabled for {ip}")
            return

        timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        color = 3066993 if status == "UP" else 15158332  # Green 3066993, Red 15158332
        status_emoji = "🟢" if status == "UP" else "🔴"
        message = f"{status_emoji} **{status}** `{ip}` {desc or ''} | Latency: {lat}ms | Consecutive: {consecutive or 0} | {timestamp}"

        sent = False

        # Email
        if config.email_enabled and config.email_recipient and config.email_user and config.email_pass:
            try:
                msg = MIMEText(message)
                msg['Subject'] = f"{status} Alert - {ip}"
                msg['From'] = config.email_user
                msg['To'] = config.email_recipient
                if config.email_use_ssl:
                    server = smtplib.SMTP_SSL(config.email_host, config.email_port)
                else:
                    server = smtplib.SMTP(config.email_host, config.email_port)
                    if config.email_use_tls:
                        server.starttls()
                server.login(config.email_user, config.email_pass)
                server.send_message(msg)
                server.quit()
                logger.info(f"Email sent successfully for {ip}")
                sent = True
            except Exception as e:
                logger.error(f"Email send failed for {ip}: {e}")
        else:
            logger.info(f"Email not configured for {ip} (missing credentials/recipient)")

        # Discord
        if config.discord_enabled and config.discord_webhook:
            try:
                timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')  # FIXED: Proper ISO 8601
                payload = {
                    "embeds": [{
                        "title": f"{status_emoji} {status}",
                        "description": f"`{ip}` {desc or ''}\nLatency: {lat}ms | Consec: {consecutive or 0}",
                        "color": color,
                        "timestamp": timestamp  # Now valid
                    }]
                }
                response = requests.post(config.discord_webhook, json=payload)
                if response.status_code == 204:
                    logger.info(f"Discord notification sent successfully for {ip}")
                    sent = True
                else:
                    logger.error(f"Discord send failed for {ip}: HTTP {response.status_code} - {response.text}")
            except Exception as e:
                logger.error(f"Discord send failed for {ip}: {e}")

        # Custom Webhook
        if config.custom_webhook_enabled and config.custom_webhook_url:
            try:
                payload = {
                    "status": status,
                    "ip": ip,
                    "description": desc or '',
                    "latency": lat,
                    "consecutive_fails": consecutive or 0,
                    "timestamp": timestamp
                }
                response = requests.post(config.custom_webhook_url, json=payload)
                if response.status_code == 200:
                    logger.info(f"Custom webhook sent successfully for {ip}")
                    sent = True
                else:
                    logger.error(f"Custom webhook failed for {ip}: HTTP {response.status_code} - {response.text}")
            except Exception as e:
                logger.error(f"Custom webhook failed for {ip}: {e}")
        else:
            logger.info(f"Custom webhook not configured for {ip}")

        if sent:
            logger.info(f"At least one notification sent for {ip}")
        else:
            logger.warning(f"No notifications sent for {ip} - check config")

def set_paused_live(ip_obj):
    with lock:
        ip = ip_obj.ip
        if ip not in LIVE:
            LIVE[ip] = {}
        now = datetime.now(timezone.utc)
        paused_until = normalize_to_utc(ip_obj.pause_until)
        paused = paused_until and paused_until > now
        LIVE[ip]['paused'] = paused
        LIVE[ip]['pause_until'] = ip_obj.pause_until.isoformat() if ip_obj.pause_until else None
        LIVE[ip]['ip_id'] = ip_obj.id
        LIVE[ip]['description'] = ip_obj.description or ''
        if 'status' not in LIVE[ip]:
            LIVE[ip]['status'] = 'UNKNOWN'
            LIVE[ip]['time'] = ''
            LIVE[ip]['latency'] = 0
            LIVE[ip]['consecutive_fails'] = 0
            LIVE[ip]['desc'] = ''
        LIVE[ip]['notif_enabled'] = ip_obj.notifications_enabled
        LIVE[ip]['quiet_enabled'] = ip_obj.quiet_hours_enabled
        LIVE[ip]['monitor_type'] = ip_obj.monitor_type or 'icmp'
        LIVE[ip]['monitor_port'] = ip_obj.monitor_port
        LIVE[ip]['monitor_url'] = ip_obj.monitor_url
        LIVE[ip]['monitor_keyword'] = ip_obj.monitor_keyword
        LIVE[ip]['interval'] = ip_obj.interval_seconds or 20
        LIVE[ip]['alert_threshold'] = ip_obj.alert_threshold
        LIVE[ip]['resend_every'] = ip_obj.resend_every  # Per-target resend_every
        LIVE[ip]['quiet_start'] = ip_obj.quiet_start
        LIVE[ip]['quiet_end'] = ip_obj.quiet_end

def do_ping(ip_id):
    with app.app_context():
        ip_obj = db.session.get(IPAddress, ip_id)
        if not ip_obj:
            logger.warning(f"IP ID {ip_id} not found in do_ping")
            return
        ip = ip_obj.ip
        monitor_type = ip_obj.monitor_type or 'icmp'
        config = Config.query.first()
        threshold = ip_obj.alert_threshold or config.alert_threshold
        resend = ip_obj.resend_every or config.resend_every
        desc = ip_obj.description or ''
        now = datetime.now(timezone.utc)
        success = False
        latency = None

        logger.info(f"Starting ping check for {ip} ({monitor_type}) - threshold: {threshold}, resend: {resend}")

        try:
            if monitor_type == 'icmp':
                # ICMP ping using pythonping
                response = ping(ip, timeout=5, size=56, count=1)
                success = response.success()
                if success:
                    latency = round(response.rtt_avg_ms, 2)
            elif monitor_type == 'tcp':
                port = ip_obj.monitor_port
                if not port:
                    raise ValueError("TCP monitor requires port")
                import socket
                import time  # Add this import if not already at top
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                start_time = time.time()  # FIXED: Start timing
                result = sock.connect_ex((ip, port))
                end_time = time.time()    # End timing
                sock.close()
                success = result == 0
                if success:
                    latency = round((end_time - start_time) * 1000, 2)
                else:
                    latency = None  # Or optionally time the failure too: (end_time - start_time) * 1000
            elif monitor_type in ['http', 'https']:
                url = ip_obj.monitor_url
                if not url:
                    raise ValueError("HTTP/HTTPS monitor requires URL")
                protocol = 'https' if monitor_type == 'https' else 'http'
                full_url = url if url.startswith(protocol) else f"{protocol}://{url}"
                response = requests.get(full_url, timeout=10, verify=False)
                success = response.status_code < 400
                if success and ip_obj.monitor_keyword:
                    success = ip_obj.monitor_keyword.lower() in response.text.lower()
                latency = round(response.elapsed.total_seconds() * 1000, 2)
            else:
                raise ValueError(f"Unknown monitor type: {monitor_type}")

        except Exception as e:
            logger.exception(f"Monitor check failed for {ip} ({monitor_type}): {e}")
            success = False

        # Get current counters from LIVE (thread-safe)
        with lock:
            current_consecutive = LIVE.get(ip, {}).get('consecutive_fails', 0)
            last_alerted = ip_obj.last_alerted_fails  # From DB

        consecutive_fails = current_consecutive + 1 if not success else 0
        alerted_this_check = False

        if success:
            # UP: Reset counters, alert if previously down
            logger.info(f"Ping {ip}: UP (latency: {latency or 0:.1f}ms, consec: {consecutive_fails})")
            if last_alerted > 0:
                send_notification(ip, "UP", lat=latency, desc=desc, consecutive=0,
                                  ip_quiet_enabled=ip_obj.quiet_hours_enabled,
                                  quiet_start=ip_obj.quiet_start, quiet_end=ip_obj.quiet_end)
                logger.info(f"Recovery alert sent for {ip} (was down for {last_alerted} fails)")
                alerted_this_check = True
            ip_obj.last_alerted_fails = 0
            latency_log = latency
        else:
            # DOWN: Check for alerts
            logger.info(f"Ping {ip}: DOWN (consec: {consecutive_fails}, last_alerted: {last_alerted})")
            if consecutive_fails >= threshold and last_alerted < threshold:
                # First alert
                send_notification(ip, "DOWN", lat=None, desc=desc, consecutive=consecutive_fails,
                                  ip_quiet_enabled=ip_obj.quiet_hours_enabled,
                                  quiet_start=ip_obj.quiet_start, quiet_end=ip_obj.quiet_end)
                ip_obj.last_alerted_fails = consecutive_fails
                logger.info(f"First DOWN alert sent for {ip} at {consecutive_fails} fails (threshold: {threshold})")
                alerted_this_check = True
            elif consecutive_fails >= last_alerted + resend:
                # Resend alert
                send_notification(ip, "DOWN", lat=None, desc=desc, consecutive=consecutive_fails,
                                  ip_quiet_enabled=ip_obj.quiet_hours_enabled,
                                  quiet_start=ip_obj.quiet_start, quiet_end=ip_obj.quiet_end)
                ip_obj.last_alerted_fails += resend
                logger.info(f"Resend DOWN alert for {ip} at {consecutive_fails} fails (resend every: {resend})")
                alerted_this_check = True
            latency_log = None

        # Persist to DB
        db.session.add(PingLog(ip_id=ip_id, success=success, latency=latency_log, timestamp=now))
        db.session.commit()

        # Update LIVE (thread-safe)
        with lock:
            if ip not in LIVE:
                LIVE[ip] = {}
            LIVE[ip]['status'] = 'UP' if success else 'FAILED'
            LIVE[ip]['time'] = now.strftime('%H:%M:%S')
            LIVE[ip]['latency'] = latency or 0
            LIVE[ip]['consecutive_fails'] = consecutive_fails
            LIVE[ip]['desc'] = desc
            # Ensure other fields are set (from set_paused_live)
            if 'ip_id' not in LIVE[ip]:
                set_paused_live(ip_obj)  # Fallback init

        logger.info(f"Updated counters for {ip}: consec={consecutive_fails}, alerted={last_alerted if not success else 0}")
        if alerted_this_check:
            logger.info(f"Alert sent for {ip}: {'UP' if success else 'DOWN'} (consec: {consecutive_fails})")

def start_pings():
    with app.app_context():
        now = datetime.now(timezone.utc)
        for ip_obj in IPAddress.query.all():
            paused_until = normalize_to_utc(ip_obj.pause_until)
            if not ip_obj.blacklist and not (paused_until and paused_until > now):
                job_id = f'ping_{ip_obj.id}'
                scheduler.add_job(do_ping, 'interval', seconds=ip_obj.interval_seconds or 20, args=[ip_obj.id], id=job_id, replace_existing=True)
                set_paused_live(ip_obj)
                logger.info(f"Started {ip_obj.monitor_type.upper()} ping job for {ip_obj.ip} (interval {ip_obj.interval_seconds}s)")

def rescan_pings():
    with app.app_context():
        now = datetime.now(timezone.utc)
        for ip_obj in IPAddress.query.all():
            paused_until = normalize_to_utc(ip_obj.pause_until)
            if paused_until and paused_until > now:
                try:
                    scheduler.remove_job(f'ping_{ip_obj.id}')
                    logger.info(f"Paused job for {ip_obj.ip}")
                except:
                    pass
            set_paused_live(ip_obj)

@app.route('/', methods=['GET'])
def index():
    search = request.args.get('search')
    with app.app_context():
        if search:
            ips = IPAddress.query.filter(
                or_(IPAddress.ip.contains(search), IPAddress.description.contains(search))
            ).filter_by(blacklist=False).all()
        else:
            ips = IPAddress.query.filter_by(blacklist=False).all()
    return render_template('index.html', ips=ips, search=search)

@app.route('/add', methods=['POST'])
def add():
    ip = request.form['ip'].strip()
    desc = request.form.get('description', '').strip()
    monitor_type = request.form.get('monitor_type', 'icmp')
    with app.app_context():
        if ip and not IPAddress.query.filter_by(ip=ip).first():
            new_ip = IPAddress(
                ip=ip, 
                description=desc, 
                notifications_enabled=True, 
                last_alerted_fails=0,
                monitor_type=monitor_type,
                interval_seconds=20
            )
            if monitor_type == 'tcp':
                port = request.form.get('port')
                if not port:
                    flash('Port is required for TCP monitoring.')
                    return redirect('/')
                new_ip.monitor_port = int(port)
            elif monitor_type in ['http', 'https']:
                url = request.form.get('url')
                if not url:
                    flash('URL is required for HTTP/HTTPS monitoring.')
                    return redirect('/')
                new_ip.monitor_url = url
                new_ip.monitor_keyword = request.form.get('keyword', '')
            db.session.add(new_ip)
            db.session.commit()
            interval = new_ip.interval_seconds or 20
            job_id = f'ping_{new_ip.id}'
            scheduler.add_job(do_ping, 'interval', seconds=interval, args=[new_ip.id],
                             id=job_id, replace_existing=True)
            do_ping(new_ip.id)
            logger.info(f"ADDED {ip} ({desc}) → {monitor_type.upper()} started (notifs enabled)")
        else:
            flash(f"IP {ip} already exists or invalid.")
            logger.warning(f"Add failed: IP {ip} already exists")
    return redirect('/')

@app.route('/del/<int:ip_id>')
def delete(ip_id):
    with app.app_context():
        ip_obj = db.session.get(IPAddress, ip_id)
        if not ip_obj:
            logger.warning(f"Delete failed: IP ID {ip_id} not found")
            return redirect('/')
        try:
            scheduler.remove_job(f'ping_{ip_id}')
            logger.info(f"Removed scheduler job for {ip_obj.ip}")
        except:
            logger.warning(f"No scheduler job to remove for {ip_obj.ip}")
        PingLog.query.filter_by(ip_id=ip_id).delete()
        db.session.delete(ip_obj)
        db.session.commit()
        logger.info(f"DELETED {ip_obj.ip}")
    return redirect('/')

@app.route('/stats/<int:ip_id>')
def stats(ip_id):
    with app.app_context():
        ip_obj = db.session.get(IPAddress, ip_id)
        if not ip_obj:
            flash('IP not found.')
            return redirect('/')

        def get_stats(days):
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            logs = db.session.query(PingLog).filter_by(ip_id=ip_id).filter(PingLog.timestamp >= cutoff).all()
            if not logs:
                return {'uptime': 0, 'avg_latency': 0, 'graph': None}
            df = pd.DataFrame([{'ts': l.timestamp, 'success': l.success, 'lat': l.latency} for l in logs])
            uptime = df['success'].mean() * 100
            avg_lat = df[df['success']]['lat'].mean() if df['success'].any() else 0
            # Graph with red crosses for downs - hide latency points for downs
            fig, ax = plt.subplots(figsize=(10, 4))
            # Plot latency line only for successful checks
            up_mask = df['success']
            if up_mask.any():
                ax.plot(df.loc[up_mask, 'ts'], df.loc[up_mask, 'lat'], 'g-', label='Latency', linewidth=2)
                ax.fill_between(df.loc[up_mask, 'ts'], df.loc[up_mask, 'lat'], color='green', alpha=0.3)
            # Red crosses for down checks at y=0
            down_mask = ~df['success']
            if down_mask.any():
                ax.scatter(df.loc[down_mask, 'ts'], [0] * down_mask.sum(), marker='x', color='red', s=100, linewidth=3, label='Down')
            ax.set_ylabel('Latency (ms)')
            ax.set_title(f'{days}-Day Stats')
            ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
            if up_mask.any() or down_mask.any():
                ax.legend(loc='upper right')
            fig.autofmt_xdate()
            buf = io.BytesIO()
            fig.savefig(buf, format='png', bbox_inches='tight')
            buf.seek(0)
            graph = base64.b64encode(buf.read()).decode()
            plt.close(fig)
            return {'uptime': round(uptime, 2), 'avg_latency': round(avg_lat, 1), 'graph': graph}

        stats_1d = get_stats(1)
        stats_7d = get_stats(7)
        stats_30d = get_stats(30)
        return render_template('stats.html', ip=ip_obj, stats_1d=stats_1d, stats_7d=stats_7d, stats_30d=stats_30d)

@app.route('/pause/<int:ip_id>', methods=['POST'])
def pause(ip_id):
    with app.app_context():
        ip_obj = db.session.get(IPAddress, ip_id)
        if not ip_obj:
            return jsonify({'status': 'error'})
        minutes_str = request.form.get('pause_until')
        try:
            pause_until = datetime.fromisoformat(minutes_str.replace('Z', '+00:00'))
            ip_obj.pause_until = pause_until
        except:
            logger.error(f"Pause failed: Invalid datetime {minutes_str}")
            return jsonify({'status': 'error'})
        db.session.commit()
        try:
            scheduler.remove_job(f'ping_{ip_id}')
            logger.info(f"Removed scheduler job for {ip_obj.ip}")
        except:
            logger.warning(f"No scheduler job to remove for {ip_obj.ip}")
        set_paused_live(ip_obj)
        logger.info(f"PAUSED {ip_obj.ip} until {ip_obj.pause_until}")
        return jsonify({'status': 'ok'})

@app.route('/resume/<int:ip_id>', methods=['POST'])
def resume(ip_id):
    with app.app_context():
        ip_obj = db.session.get(IPAddress, ip_id)
        if not ip_obj:
            logger.error(f"Resume failed: IP ID {ip_id} not found")
            return jsonify({'status': 'error'})
        ip_obj.pause_until = None
        db.session.commit()
        job_id = f'ping_{ip_id}'
        interval = ip_obj.interval_seconds or 20
        scheduler.add_job(do_ping, 'interval', seconds=interval, args=[ip_id], id=job_id, replace_existing=True)
        do_ping(ip_id)
        now_str = datetime.now(timezone.utc).strftime('%H:%M:%S')
        with lock:
            if ip_obj.ip in LIVE:
                LIVE[ip_obj.ip]['paused'] = False
                LIVE[ip_obj.ip]['pause_until'] = None
        logger.info(f"RESUMED {ip_obj.ip}")
        return jsonify({'status': 'ok'})

@app.route('/live')
def live():
    with lock:
        return jsonify(LIVE)

@app.route('/graph/<ip>')
def graph(ip):
    hours = int(request.args.get('hours', 1))
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    with app.app_context():
        logs = db.session.query(PingLog).join(IPAddress).filter(
            IPAddress.ip == ip,
            PingLog.timestamp >= cutoff
        ).order_by(PingLog.timestamp.asc()).all()
    max_points = 1000
    if len(logs) > max_points:
        step = max(1, len(logs) // max_points)
        logs = logs[::step]
    fmt = '%H:%M' if hours < 24 else '%m-%d %H'
    return jsonify({
        'times': [l.timestamp.strftime(fmt) for l in logs],
        'latency': [l.latency if l.success else 0 for l in logs],
        'success': [int(l.success) for l in logs]
    })

@app.route('/webhook/add', methods=['POST'])
def webhook():
    data = request.get_json() or {}
    ip = data.get('ip')
    desc = data.get('description', '')
    with app.app_context():
        if ip and not IPAddress.query.filter_by(ip=ip).first():
            new_ip = IPAddress(
                ip=ip, 
                description=desc, 
                notifications_enabled=True, 
                last_alerted_fails=0,
                monitor_type='icmp',
                interval_seconds=20
            )
            db.session.add(new_ip)
            db.session.commit()
            interval = new_ip.interval_seconds or 20
            job_id = f'ping_{new_ip.id}'
            scheduler.add_job(do_ping, 'interval', seconds=interval, args=[new_ip.id], id=job_id)
            do_ping(new_ip.id)
            logger.info(f"Webhook added {ip} ({desc}) → ping started")
        else:
            logger.warning(f"Webhook add failed: IP {ip} already exists")
    return jsonify({'status': 'ok'})

@app.route('/update_ip/<int:ip_id>', methods=['POST'])
def update_ip(ip_id):
    with app.app_context():
        ip_obj = db.session.get(IPAddress, ip_id)
        if not ip_obj:
            return jsonify({'status': 'error'})
        data = request.get_json() or {}
        old_interval = ip_obj.interval_seconds
        for key, val in data.items():
            if key in ['alert_threshold', 'quiet_start', 'quiet_end', 'monitor_port', 'interval_seconds', 'resend_every'] and val is not None:
                setattr(ip_obj, key, int(val))
            elif key in ['monitor_url', 'monitor_keyword', 'monitor_type']:
                setattr(ip_obj, key, val)
            elif key in ['notifications_enabled', 'quiet_hours_enabled']:
                setattr(ip_obj, key, bool(val))
        db.session.commit()
        # Reschedule if interval changed
        if old_interval != ip_obj.interval_seconds:
            try:
                scheduler.remove_job(f'ping_{ip_id}')
            except:
                pass
            now = datetime.now(timezone.utc)
            paused_until = normalize_to_utc(ip_obj.pause_until)
            if not (paused_until and paused_until > now) and not ip_obj.blacklist:
                new_interval = ip_obj.interval_seconds or 20
                scheduler.add_job(do_ping, 'interval', seconds=new_interval, args=[ip_id], id=f'ping_{ip_id}', replace_existing=True)
                do_ping(ip_id)
        set_paused_live(ip_obj)
        logger.info(f"Updated config for {ip_obj.ip}")
        return jsonify({'status': 'ok'})

@app.route('/toggle_notif/<int:ip_id>', methods=['POST'])
def toggle_notif(ip_id):
    with app.app_context():
        ip_obj = db.session.get(IPAddress, ip_id)
        if ip_obj:
            ip_obj.notifications_enabled = not ip_obj.notifications_enabled
            db.session.commit()
            logger.info(f"Notifications {'enabled' if ip_obj.notifications_enabled else 'disabled'} for {ip_obj.ip}")
            set_paused_live(ip_obj)
            return jsonify({'status': 'ok'})
        return jsonify({'status': 'error'})

@app.route('/toggle_quiet/<int:ip_id>', methods=['POST'])
def toggle_quiet(ip_id):
    with app.app_context():
        ip_obj = db.session.get(IPAddress, ip_id)
        if ip_obj:
            ip_obj.quiet_hours_enabled = not ip_obj.quiet_hours_enabled
            db.session.commit()
            logger.info(f"Quiet hours {'enabled' if ip_obj.quiet_hours_enabled else 'disabled'} for {ip_obj.ip}")
            set_paused_live(ip_obj)
            return jsonify({'status': 'ok'})
        return jsonify({'status': 'error'})

@app.route('/config', methods=['GET', 'POST'])
def config():
    with app.app_context():
        c = db.session.get(Config, 1)
        if request.method == 'POST':
            c.email_host = request.form.get('email_host', c.email_host)
            c.email_port = int(request.form.get('email_port', c.email_port)) if request.form.get('email_port') else c.email_port
            c.email_user = request.form.get('email_user', c.email_user)
            c.email_pass = request.form.get('email_pass', c.email_pass)
            c.email_recipient = request.form.get('email_recipient', c.email_recipient)
            c.email_use_tls = 'email_use_tls' in request.form
            c.email_use_ssl = 'email_use_ssl' in request.form
            c.email_enabled = 'email_enabled' in request.form
            c.discord_webhook = request.form.get('discord_webhook', c.discord_webhook)
            c.discord_enabled = 'discord_enabled' in request.form
            c.custom_webhook_url = request.form.get('custom_webhook_url', c.custom_webhook_url)
            c.custom_webhook_enabled = 'custom_webhook_enabled' in request.form
            c.alert_threshold = int(request.form.get('alert_threshold', c.alert_threshold)) if request.form.get('alert_threshold') else c.alert_threshold
            c.resend_every = int(request.form.get('resend_every', c.resend_every)) if request.form.get('resend_every') else c.resend_every
            c.quiet_hours_start = int(request.form.get('quiet_hours_start', c.quiet_hours_start)) if request.form.get('quiet_hours_start') else c.quiet_hours_start
            c.quiet_hours_end = int(request.form.get('quiet_hours_end', c.quiet_hours_end)) if request.form.get('quiet_hours_end') else c.quiet_hours_end
            db.session.commit()
            flash('Configuration saved.')
        return render_template('config.html', config=c)

@app.route('/config_json')
def config_json():
    with app.app_context():
        c = db.session.get(Config, 1)
        return jsonify({
            'alert_threshold': c.alert_threshold,
            'resend_every': c.resend_every,  # Include global resend_every
            'quiet_hours_start': c.quiet_hours_start,
            'quiet_hours_end': c.quiet_hours_end
        })

scheduler.add_job(rescan_pings, 'interval', minutes=1)

with app.app_context():
    start_pings()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)