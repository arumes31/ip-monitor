# app.py
import os
import logging
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, jsonify, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from apscheduler.schedulers.background import BackgroundScheduler
from pythonping import ping
import smtplib
from email.mime.text import MIMEText
import threading
import requests
import matplotlib.pyplot as plt
import io
import base64
import pandas as pd
from sqlalchemy import Index

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////app/db/monitor.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class IPAddress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(255))
    blacklist = db.Column(db.Boolean, default=False)
    pause_until = db.Column(db.DateTime(timezone=True))  # ← Add timezone=True
    notifications_enabled = db.Column(db.Boolean, default=True)
    quiet_hours_enabled = db.Column(db.Boolean, default=False)
    last_alerted_fails = db.Column(db.Integer, default=0)

class PingLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_id = db.Column(db.Integer, db.ForeignKey('ip_address.id'))
    timestamp = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    success = db.Column(db.Boolean)
    latency = db.Column(db.Float)
    
    # Add this: Composite index for efficient queries by ip_id + timestamp
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
    quiet_hours_start = db.Column(db.Integer, default=22)  # e.g., 10 PM UTC
    quiet_hours_end = db.Column(db.Integer, default=6)    # e.g., 6 AM UTC

with app.app_context():
    db.create_all()  # This auto-creates the index via __table_args__
    c = Config.query.first()
    if not c:
        db.session.add(Config())
        db.session.commit()

LIVE = {}
lock = threading.Lock()
scheduler = BackgroundScheduler()
scheduler.start()

def is_quiet_hours(config, ip_quiet_enabled):
    if not ip_quiet_enabled:
        return False
    now_hour = datetime.now(timezone.utc).hour
    start = config.quiet_hours_start
    end = config.quiet_hours_end
    if start < end:
        return start <= now_hour < end
    else:  # Wraps midnight
        return now_hour >= start or now_hour < end

def send_notification(ip, status, lat=None, desc=None, consecutive=None, ip_quiet_enabled=False):
    config = Config.query.first()
    if is_quiet_hours(config, ip_quiet_enabled):
        logger.info(f"Quiet hours active for {ip}: Skipping alert {status}")
        return

    ip_obj = IPAddress.query.filter_by(ip=ip).first()
    if not ip_obj or not ip_obj.notifications_enabled:
        return

    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    color = "green" if status == "UP" else "red"
    status_emoji = "🟢" if status == "UP" else "🔴"

    # Improved HTML email
    html_body = f"""
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
            <h2 style="color: {color}; text-align: center;">{status_emoji} Ping Alert: {status}</h2>
            <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                <tr><td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>IP:</strong></td><td style="padding: 8px; border-bottom: 1px solid #eee;">{ip}</td></tr>
                <tr><td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Description:</strong></td><td style="padding: 8px; border-bottom: 1px solid #eee;">{desc or 'N/A'}</td></tr>
                <tr><td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Status:</strong></td><td style="padding: 8px; border-bottom: 1px solid #eee;">{status}</td></tr>
                <tr><td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Latency:</strong></td><td style="padding: 8px; border-bottom: 1px solid #eee;">{f'{lat}ms' if lat else 'N/A'}</td></tr>
                <tr><td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Consecutive Fails:</strong></td><td style="padding: 8px; border-bottom: 1px solid #eee;">{consecutive if consecutive is not None else 0}</td></tr>
                <tr><td style="padding: 8px;"><strong>Timestamp:</strong></td><td style="padding: 8px;">{timestamp}</td></tr>
            </table>
            <p style="text-align: center; font-style: italic;">This is an automated alert from Ping Monitor.</p>
        </div>
    </body>
    </html>
    """

    to_addr = config.email_recipient or config.email_user
    if config.email_enabled and config.email_user and config.email_pass and to_addr:
        try:
            e_msg = MIMEText(html_body, 'html')
            e_msg['Subject'] = f"{status_emoji} Ping Alert: {ip} - {status}"
            e_msg['From'] = config.email_user
            e_msg['To'] = to_addr
            if config.email_use_ssl:
                with smtplib.SMTP_SSL(config.email_host, config.email_port) as server:
                    server.login(config.email_user, config.email_pass)
                    server.send_message(e_msg)
            else:
                with smtplib.SMTP(config.email_host, config.email_port) as server:
                    if config.email_use_tls:
                        server.starttls()
                    server.login(config.email_user, config.email_pass)
                    server.send_message(e_msg)
            logger.info(f"HTML Mail sent for {ip} ({status})")
        except Exception as e:
            logger.error(f"Mail error for {ip}: {e}")

    if config.discord_enabled and config.discord_webhook:
        try:
            consecutive_val = consecutive if consecutive is not None else 0
            embed = {
                "title": f"{status_emoji} Ping Alert: {status}",
                "description": f"Ping for **{ip}** {f'({desc})' if desc else ''}",
                "color": 0x00ff00 if status == "UP" else 0xff0000,
                "fields": [
                    {"name": "Status", "value": status, "inline": True},
                    {"name": "Latency", "value": f"{lat}ms" if lat else "N/A", "inline": True},
                    {"name": "Consecutive Fails", "value": str(consecutive_val), "inline": True},
                    {"name": "Timestamp", "value": timestamp, "inline": False}
                ],
                "footer": {"text": "Ping Monitor"}
            }
            requests.post(config.discord_webhook, json={'embeds': [embed]})
            logger.info(f"Discord embed sent for {ip} ({status})")
        except Exception as e:
            logger.error(f"Discord error for {ip}: {e}")

    if config.custom_webhook_enabled and config.custom_webhook_url:
        try:
            payload = {
                'ip': ip,
                'status': status,
                'latency': lat,
                'description': desc,
                'consecutive_fails': consecutive if consecutive is not None else 0,
                'timestamp': timestamp
            }
            requests.post(config.custom_webhook_url, json=payload)
            logger.info(f"Custom webhook sent for {ip} ({status})")
        except Exception as e:
            logger.error(f"Custom webhook error for {ip}: {e}")

def is_paused(pause_until):
    if not pause_until:
        return False
    # FIXED: Make pause_until aware if naive
    if pause_until.tzinfo is None:
        pause_until = pause_until.replace(tzinfo=timezone.utc)
    return pause_until > datetime.now(timezone.utc)

def get_consecutive_fails(ip_id):
    recent_logs = PingLog.query.filter_by(ip_id=ip_id).order_by(PingLog.timestamp.desc()).limit(100).all()
    consecutive = 0
    for log in recent_logs:
        if log.success:
            break
        consecutive += 1
    return consecutive

def do_ping(ip_id):
    with app.app_context():
        ip_obj = db.session.get(IPAddress, ip_id)
        if not ip_obj:
            return
        ip = ip_obj.ip
        desc = ip_obj.description
        ip_quiet_enabled = ip_obj.quiet_hours_enabled

        if is_paused(ip_obj.pause_until):
            return

        config = Config.query.first()
        threshold = config.alert_threshold
        resend_every = config.resend_every

        # Get previous status before ping
        with lock:
            prev_data = LIVE.get(ip, {})
            prev_status = prev_data.get('status', 'UP')
            prev_consecutive = prev_data.get('consecutive_fails', 0)

        try:
            response = ping(ip, timeout=5, count=1, size=56)
            success = response.success(option=3)
            latency = round(response.rtt_avg_ms) if success else 0
        except Exception as e:
            logger.error(f"Ping error for {ip}: {e}")
            success = False
            latency = 0

        # Log to DB
        log = PingLog(ip_id=ip_id, success=success, latency=latency)
        db.session.add(log)
        db.session.commit()

        # Determine notification
        notify = False
        notif_status = None
        notif_consecutive = None
        notif_latency = latency if success else None

        if success:
            consecutive = 0
            if prev_status == 'FAILED' and prev_consecutive > 0:
                # Recovery notification
                notify = True
                notif_status = 'UP'
                notif_consecutive = 0
                logger.info(f"RECOVERY: {ip} back UP after {prev_consecutive} fails")
            # Reset last_alerted_fails on recovery
            ip_obj.last_alerted_fails = 0
        else:
            consecutive = get_consecutive_fails(ip_id)
            if consecutive >= threshold:
                last_alerted = ip_obj.last_alerted_fails
                if consecutive >= last_alerted + resend_every:
                    notify = True
                    notif_status = 'FAILED'
                    notif_consecutive = consecutive
                    ip_obj.last_alerted_fails = consecutive
                    logger.info(f"ALERT: {ip} FAILED ({consecutive} consecutive fails)")

        db.session.commit()

        if notify:
            send_notification(ip, notif_status, notif_latency, desc, notif_consecutive, ip_quiet_enabled)

        # Update LIVE
        status = 'UP' if success else 'FAILED'
        color = 'green' if success else 'red'
        now_str = datetime.now(timezone.utc).strftime('%H:%M:%S')

        with lock:
            LIVE[ip] = {
                'status': status,
                'color': color,
                'time': now_str,
                'latency': latency,
                'consecutive_fails': consecutive,
                'paused': is_paused(ip_obj.pause_until),
                'pause_until': ip_obj.pause_until.isoformat() if ip_obj.pause_until else None,
                'notif_enabled': ip_obj.notifications_enabled,
                'quiet_enabled': ip_quiet_enabled
            }

def start_pings():
    for ip_obj in IPAddress.query.all():
        if not is_paused(ip_obj.pause_until):
            job_id = f'ping_{ip_obj.id}'
            scheduler.add_job(do_ping, 'interval', seconds=20, args=[ip_obj.id], id=job_id, replace_existing=True)
            do_ping(ip_obj.id)
            logger.info(f"Started ping for {ip_obj.ip}")

def rescan_pings():
    with app.app_context():
        for ip_obj in IPAddress.query.all():
            if not is_paused(ip_obj.pause_until):
                job_id = f'ping_{ip_obj.id}'
                if scheduler.get_job(job_id) is None:
                    scheduler.add_job(do_ping, 'interval', seconds=20, args=[ip_obj.id], id=job_id, replace_existing=True)
                    do_ping(ip_obj.id)
                    logger.info(f"Rescanned and restarted ping for {ip_obj.ip}")

def set_paused_live(ip_obj):
    with lock:
        if ip_obj.ip in LIVE:
            LIVE[ip_obj.ip]['paused'] = True
            LIVE[ip_obj.ip]['pause_until'] = ip_obj.pause_until.isoformat() if ip_obj.pause_until else None

def get_stats(ip_id, hours):
    now_utc = datetime.now(timezone.utc)
    cutoff = now_utc - timedelta(hours=hours)
    cutoff_naive = cutoff.replace(tzinfo=None)  # Naive for DB compatibility
    
    logs = PingLog.query.filter(
        PingLog.ip_id == ip_id,
        PingLog.timestamp >= cutoff_naive
    ).order_by(PingLog.timestamp).all()
    
    if not logs:
        return {'uptime': 0, 'avg_latency': 0, 'graph': None}
    
    total_pings = len(logs)
    successful_pings = sum(1 for log in logs if log.success)
    uptime = (successful_pings / total_pings * 100) if total_pings > 0 else 0
    
    latencies = [log.latency for log in logs if log.success and log.latency is not None]
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    
    # Generate enhanced graph with visible failures
    if logs:
        fig, ax = plt.subplots(figsize=(10, 4))
        
        # Times in hours ago
        times = [(log.timestamp - cutoff_naive).total_seconds() / 3600 for log in logs]
        
        # Separate success and failure points for visibility
        success_times = [t for t, log in zip(times, logs) if log.success]
        success_flags = [1] * len(success_times)  # All 1 for up
        failure_times = [t for t, log in zip(times, logs) if not log.success]
        failure_flags = [0] * len(failure_times)  # All 0 for down
        
        # Plot green line/markers for successes (Up)
        if success_times:
            ax.plot(success_times, success_flags, marker='o', color='green', label='Up (Success)', linewidth=2)
        
        # Plot red markers/bars for failures (Down) - prominent visibility
        if failure_times:
            # Option 1: Red scatter points (simple, like live graph)
            ax.scatter(failure_times, failure_flags, color='red', s=100, marker='x', label='Down (Failure)', zorder=5)
            
            # Option 2: Uncomment below for bar-style (like live downtime bars; adjust width as needed)
            # bar_width = 0.05  # Narrow bars
            # ax.bar(failure_times, [1] * len(failure_times), width=bar_width, bottom=0, color='red', alpha=0.7, label='Downtime', zorder=3)
        
        # Latency on secondary axis (blue line)
        latency_times = [t for t, log in zip(times, logs) if log.success and log.latency is not None]
        if latency_times:
            latencies_plot = [log.latency for log in logs if log.success and log.latency is not None]
            ax2 = ax.twinx()
            ax2.plot(latency_times, latencies_plot, color='blue', alpha=0.7, label='Latency (ms)')
            ax2.set_ylabel('Latency (ms)', color='blue')
            ax2.tick_params(axis='y', labelcolor='blue')
        
        ax.set_xlabel('Hours Ago')
        ax.set_ylabel('Status (1=Up, 0=Down)')
        ax.set_title(f'{hours}-Hour Stats for IP {ip_id} (Uptime: {uptime}%, Failures: {total_pings - successful_pings})')
        ax.set_ylim(-0.1, 1.1)  # Buffer for visibility
        ax.legend(loc='upper left')
        plt.tight_layout()
        
        img_buffer = io.BytesIO()
        plt.savefig(img_buffer, format='png', bbox_inches='tight', dpi=100)
        img_buffer.seek(0)
        graph_b64 = base64.b64encode(img_buffer.getvalue()).decode('utf-8')
        plt.close(fig)
    else:
        graph_b64 = None
    
    return {
        'uptime': round(uptime, 2),
        'avg_latency': round(avg_latency, 2),
        'graph': graph_b64
    }
    
@app.route('/', methods=['GET'])
def index():
    search = request.args.get('search', '')
    ips = IPAddress.query.filter_by(blacklist=False).all()
    if search:
        ips = [ip for ip in ips if search in ip.ip.lower() or search in (ip.description or '').lower()]
    
    # Sort by live status: FAILED first (by consecutive_fails desc), then PAUSED, then UP
    with lock:
        live_statuses = {ip.ip: LIVE.get(ip.ip, {'status': 'UP', 'paused': False}) for ip in ips}
    
    def sort_key(ip):
        live = live_statuses[ip.ip]
        status = live['status']
        paused = live.get('paused', False)
        if status == 'FAILED':
            return (0, -live.get('consecutive_fails', 0), ip.id)  # FAILED first, most fails first, then ID
        elif paused:
            return (1, 0, ip.id)  # PAUSED second
        else:
            return (2, 0, ip.id)  # UP last
    
    ips = sorted(ips, key=sort_key)
    
    return render_template('index.html', ips=ips, search=search)

@app.route('/stats/<int:ip_id>')
def stats(ip_id):
    ip = db.session.get(IPAddress, ip_id)
    if not ip:
        return redirect('/')
    stats_1d = get_stats(ip_id, 24)
    stats_7d = get_stats(ip_id, 168)
    stats_30d = get_stats(ip_id, 720)
    return render_template('stats.html', ip=ip, stats_1d=stats_1d, stats_7d=stats_7d, stats_30d=stats_30d)

@app.route('/config', methods=['GET', 'POST'])
def config():
    c = Config.query.first()
    if request.method == 'POST':
        c.email_host = request.form.get('email_host', c.email_host)
        c.email_port = int(request.form.get('email_port', c.email_port))
        c.email_user = request.form.get('email_user', c.email_user)
        c.email_pass = request.form.get('email_pass', c.email_pass)
        c.email_recipient = request.form.get('email_recipient', c.email_recipient)
        c.email_use_tls = request.form.get('email_use_tls') == 'on'
        c.email_use_ssl = request.form.get('email_use_ssl') == 'on'
        c.email_enabled = request.form.get('email_enabled') == 'on'
        c.discord_webhook = request.form.get('discord_webhook', c.discord_webhook)
        c.discord_enabled = request.form.get('discord_enabled') == 'on'
        c.custom_webhook_url = request.form.get('custom_webhook_url', c.custom_webhook_url)
        c.custom_webhook_enabled = request.form.get('custom_webhook_enabled') == 'on'
        c.alert_threshold = int(request.form.get('alert_threshold', c.alert_threshold))
        c.resend_every = int(request.form.get('resend_every', c.resend_every))
        c.quiet_hours_start = int(request.form.get('quiet_hours_start', c.quiet_hours_start))
        c.quiet_hours_end = int(request.form.get('quiet_hours_end', c.quiet_hours_end))
        db.session.commit()
        logger.info("Config updated")
        return redirect(url_for('config'))
    return render_template('config.html', config=c)

@app.route('/toggle_notif/<int:ip_id>', methods=['POST'])
def toggle_notif(ip_id):
    ip_obj = db.session.get(IPAddress, ip_id)
    if not ip_obj:
        return jsonify({'status': 'error'})
    ip_obj.notifications_enabled = not ip_obj.notifications_enabled
    db.session.commit()
    with lock:
        if ip_obj.ip in LIVE:
            LIVE[ip_obj.ip]['notif_enabled'] = ip_obj.notifications_enabled
    status = 'enabled' if ip_obj.notifications_enabled else 'disabled'
    logger.info(f"Notifications {status} for {ip_obj.ip}")
    return jsonify({'status': 'ok', 'enabled': ip_obj.notifications_enabled})

@app.route('/toggle_quiet/<int:ip_id>', methods=['POST'])
def toggle_quiet(ip_id):
    ip_obj = db.session.get(IPAddress, ip_id)
    if not ip_obj:
        return jsonify({'status': 'error'})
    ip_obj.quiet_hours_enabled = not ip_obj.quiet_hours_enabled
    db.session.commit()
    with lock:
        if ip_obj.ip in LIVE:
            LIVE[ip_obj.ip]['quiet_enabled'] = ip_obj.quiet_hours_enabled
    status = 'enabled' if ip_obj.quiet_hours_enabled else 'disabled'
    logger.info(f"Quiet hours {status} for {ip_obj.ip}")
    return jsonify({'status': 'ok', 'enabled': ip_obj.quiet_hours_enabled})

@app.route('/pause/<int:ip_id>', methods=['POST'])
def pause(ip_id):
    ip_obj = db.session.get(IPAddress, ip_id)
    if not ip_obj:
        logger.error(f"Pause failed: IP ID {ip_id} not found")
        return jsonify({'status': 'error'})

    pause_until_str = request.form.get('pause_until')
    if pause_until_str:
        try:
            ip_obj.pause_until = datetime.fromisoformat(pause_until_str).replace(tzinfo=timezone.utc)
        except ValueError:
            logger.error(f"Pause failed: Invalid pause_until format {pause_until_str}")
            return jsonify({'status': 'error'})
    else:
        minutes_str = request.form.get('minutes')
        if minutes_str and minutes_str.isdigit():
            minutes = int(minutes_str)
            ip_obj.pause_until = datetime.now(timezone.utc) + timedelta(minutes=minutes)
        else:
            logger.error(f"Pause failed: Invalid minutes {minutes_str}")
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
    ip_obj = db.session.get(IPAddress, ip_id)
    if not ip_obj:
        logger.error(f"Resume failed: IP ID {ip_id} not found")
        return jsonify({'status': 'error'})
    ip_obj.pause_until = None
    db.session.commit()
    job_id = f'ping_{ip_id}'
    scheduler.add_job(do_ping, 'interval', seconds=20, args=[ip_id], id=job_id, replace_existing=True)
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
    logs = PingLog.query.join(IPAddress).filter(IPAddress.ip == ip, PingLog.timestamp >= cutoff).order_by(PingLog.timestamp).all()
    return jsonify({
        'times': [l.timestamp.strftime('%H:%M') for l in logs],
        'latency': [l.latency if l.success else 0 for l in logs],
        'success': [l.success for l in logs]
    })

@app.route('/add', methods=['POST'])
def add():
    ip = request.form['ip'].strip()
    desc = request.form.get('description', '').strip()
    if ip and not IPAddress.query.filter_by(ip=ip).first():
        new_ip = IPAddress(ip=ip, description=desc, notifications_enabled=True, last_alerted_fails=0)
        db.session.add(new_ip)
        db.session.commit()
        job_id = f'ping_{new_ip.id}'
        scheduler.add_job(do_ping, 'interval', seconds=20, args=[new_ip.id],
                         id=job_id, replace_existing=True)
        do_ping(new_ip.id)
        logger.info(f"ADDED {ip} ({desc}) → ping started (notifs enabled)")
    else:
        logger.warning(f"Add failed: IP {ip} already exists")
    return redirect('/')

@app.route('/del/<int:ip_id>')
def delete(ip_id):
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

@app.route('/webhook/add', methods=['POST'])
def webhook():
    data = request.get_json() or {}
    ip = data.get('ip')
    desc = data.get('description', '')
    if ip and not IPAddress.query.filter_by(ip=ip).first():
        new_ip = IPAddress(ip=ip, description=desc, notifications_enabled=True, last_alerted_fails=0)
        db.session.add(new_ip)
        db.session.commit()
        job_id = f'ping_{new_ip.id}'
        scheduler.add_job(do_ping, 'interval', seconds=20, args=[new_ip.id], id=job_id)
        do_ping(new_ip.id)
        logger.info(f"Webhook added {ip} ({desc}) → ping started")
    else:
        logger.warning(f"Webhook add failed: IP {ip} already exists")
    return jsonify({'status': 'ok'})

scheduler.add_job(rescan_pings, 'interval', minutes=1)

with app.app_context():
    start_pings()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)