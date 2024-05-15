from datetime import datetime, timezone
import socket
from flask import jsonify, request
from email_sender import send_email
import logging
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, flash, render_template, request, redirect, url_for
from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy.orm import sessionmaker
import traceback
import requests
import whois  # Import the 'whois' module for domain expiry check
import telebot  # Import the Telebot library for Telegram integration
from werkzeug.security import generate_password_hash, check_password_hash
from flask import g

# Import the SSL checking function
from ssl_checker import check_ssl_expiry  
import threading

from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user




# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://dbusername:dbpassword@localhost/dbname'
db = SQLAlchemy(app)
engine = db.create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
Session = sessionmaker(bind=engine)

# Set a secret key
app.secret_key = 'your_secret_key_here'

# Initialize Telebot with your Telegram bot token
telegram_bot_token = 'ENTER YOUR TELEGRAM API KEY HERE'
bot = telebot.TeleBot(telegram_bot_token)

#login authenication
# Custom error handler for 401 Unauthorized
@app.errorhandler(401)
def unauthorized(error):
    return render_template('unauthorized.html'), 401

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# Define the User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)


# Dictionary to hold locks for each website ID
website_locks = {}

# Define the Website model
class Website(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    url = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(255), default="Unknown")  # Updated to string type
    prev_status = db.Column(db.String(255), default="Unknown")  # Added previous status
    ssl_expiry = db.Column(db.DateTime)
    domain_expiry = db.Column(db.DateTime)
    email_notifications = db.Column(db.Boolean, default=False)
    email_notification_email = db.Column(db.String(255))
    telegram_notifications = db.Column(db.Boolean, default=False)
    telegram_notification_phone = db.Column(db.String(20))
    status_history = db.relationship('StatusHistory', backref='website', lazy=True, cascade="all, delete-orphan")  # Add cascade parameter
    checking_interval = db.Column(db.Integer, default=60)  # Default interval is 60 seconds
    email_sent_up = db.Column(db.Boolean, default=False)  # Flag to track if email for up status has been sent
    email_sent_down = db.Column(db.Boolean, default=False)  # Flag to track if email for down status has been sent
    telegram_sent_up = db.Column(db.Boolean, default=False)  # Flag for Telegram notification sent for website up
    telegram_sent_down = db.Column(db.Boolean, default=False)  # Flag for Telegram notification sent for website down
    email_sent_domain_expiry = db.Column(db.Boolean, default=False)
    telegram_sent_domain_expiry = db.Column(db.Boolean, default=False)
    


class StatusHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    website_id = db.Column(db.Integer, db.ForeignKey('website.id'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status_code = db.Column(db.Integer, nullable=False)



    def __init__(self, website_id, status_code):
        self.website_id = website_id
        self.status_code = status_code

# Function to create the tables
def create_tables():
    with app.app_context():
        db.create_all()
        
@app.before_request
def before_request():
    g.user = current_user
# Flask-Login user loader function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password!', 'error')
    return render_template('login.html')

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

        


# Define routes and views below this lines
@app.route('/')
def index():
    with app.app_context():
        websites = Website.query.all()
        now = datetime.now()  # Get the current date and time
        return render_template('index.html', websites=websites, now=now)

@app.route('/check_status', methods=['POST'])
def check_status():
    with app.app_context():
        websites = Website.query.all()
        for website in websites:
            try:
                response = requests.get(website.url)
                status_code = response.status_code
                website.prev_status = website.status
                website.status = status_code
                
                if website.prev_status != website.status:
                    # Send email notification for status change
                    if website.email_notifications:
                        if website.status == 200:
                            subject = f"Website {website.name} is back up"
                            body = f"The website {website.name} is now back up. URL: {website.url}"
                            send_email(website.email_notification_email, subject, body)
                            website.email_sent_up = True
                        else:
                            subject = f"Website {website.name} is down"
                            body = f"The website {website.name} is currently down. URL: {website.url}"
                            send_email(website.email_notification_email, subject, body)
                            website.email_sent_down = True
                            

                try:
                    expiry_date = check_ssl_expiry(website.url)
                    website.ssl_expiry = expiry_date
                except Exception as e:
                    logger.error(f"SSL Certificate Error: {e}")
                    
                # Send Telegram notification for status change
                if website.telegram_notifications:
                    # Check if the status has changed
                    if website.prev_status != website.status:
                        if website.status == 200:
                            message = f"The website {website.name} is now back up. URL: {website.url}"
                        else:
                            message = f"The website {website.name} is currently down. URL: {website.url}"
                        send_telegram_message(website.telegram_notification_phone, message)

                db.session.commit()
            except requests.RequestException as e:
                website.prev_status = website.status
                website.status = -1

                db.session.commit()

        flash('Status checked for all websites.', 'success')
    return redirect(url_for('index'))



@app.route('/website/add', methods=['GET', 'POST'])
@login_required
def add_website():
    if request.method == 'POST':
        with app.app_context():
            name = request.form['name']
            url = request.form['url']
            interval = request.form['interval']
            email_notifications = 'email_notifications' in request.form
            email_notification_email = request.form.get('email_notification_email', '')
            telegram_notifications = 'telegram_notifications' in request.form
            telegram_notification_phone = request.form.get('telegram_notification_phone', '')
            # Check if the URL already exists
            existing_website = Website.query.filter_by(url=url).first()
            if existing_website:
                flash('The website is already in the monitoring list.', 'error')
                return redirect(url_for('add_website'))
            
            website = Website(name=name, url=url, checking_interval=int(interval), email_notifications=email_notifications,
                              email_notification_email=email_notification_email, telegram_notifications=telegram_notifications,
                              telegram_notification_phone=telegram_notification_phone)
            db.session.add(website)
            db.session.commit()
            
            # Add the new website to the scheduler
            scheduler.add_job(check_website_status, 'interval', seconds=website.checking_interval, args=[website.id], max_instances=1)
            
            flash('Website added successfully.', 'success')
        return redirect(url_for('index'))
    else:
        return render_template('add_website.html')


@app.route('/website/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_website(id):
    with app.app_context():
        website = Website.query.get_or_404(id)
        if request.method == 'POST':
            website.name = request.form['name']
            website.url = request.form['url']
            website.checking_interval = int(request.form['interval'])
            website.email_notifications = 'email_notifications' in request.form
            website.email_notification_email = request.form.get('email_notification_email', '')
            website.telegram_notifications = 'telegram_notifications' in request.form
            website.telegram_notification_phone = request.form.get('telegram_notification_phone', '')
            db.session.commit()
            flash('Website updated successfully.', 'success')
            return redirect(url_for('index'))
        else:
            return render_template('edit_website.html', website=website)

@app.route('/website/<int:id>/delete', methods=['POST'])
@login_required
def delete_website(id):
    with app.app_context():
        website = Website.query.get_or_404(id)
        # Delete associated status history records
        StatusHistory.query.filter_by(website_id=id).delete()
        # Now delete the website
        db.session.delete(website)
        db.session.commit()
        flash('Website deleted successfully.', 'success')
        return redirect(url_for('index'))


# Function to check domain expiry
def check_domain_expiry(url):
    try:
        domain_info = whois.whois(url)
        if isinstance(domain_info.expiration_date, list):
            # Return the first expiry date if there are multiple
            expiry_date = domain_info.expiration_date[0]
        else:
            expiry_date = domain_info.expiration_date
        return expiry_date
    except Exception as e:
        print(f"Domain Expiry Error: {e}")
        return None



import logging
import traceback

# Define a logger for this module
logger = logging.getLogger(__name__)

def check_website_status(website_id):
    # Check if a lock exists for the website ID, create one if not
    logger.debug(f"Checking website status for website ID: {website_id}")
    if website_id not in website_locks:
        website_locks[website_id] = threading.Lock()

    # Acquire the lock for the website ID
    with website_locks[website_id]:
        with app.app_context():
            website = Website.query.get(website_id)
            if website:
                try:
                    response = requests.get(website.url)
                    status_code = response.status_code

                    # Assign status code to website status
                    website.prev_status = website.status
                    website.status = status_code

                    # Check if the status has changed
                    if website.prev_status != website.status:
                        # Send email notification for websites that were down and are now up
                        if website.email_notifications and website.prev_status != 200 and website.status == 200 and not website.email_sent_up:
                            subject = f"Website {website.name} is back up"
                            body = f"The website {website.name} is now back up. URL: {website.url}"
                            send_email(website.email_notification_email, subject, body)
                            website.email_sent_up = True  # Set flag to indicate email has been sent
                            website.email_sent_down = False

                        # Send email notification for websites that are down
                        if website.email_notifications and (website.prev_status == 200 or website.prev_status != 200) and website.status != 200 and not website.email_sent_down:
                            subject = f"Website {website.name} is down"
                            body = f"The website {website.name} is currently down. URL: {website.url}"
                            send_email(website.email_notification_email, subject, body)
                            website.email_sent_down = True  # Set flag to indicate email has been sent
                            website.email_sent_up = False
                            
                            
                    print("Debugging: eda email sent up:", website.email_sent_up)
                    print("Debugging: eda email sent down:", website.email_sent_down)

                            
                            
                    # # Reset email_sent flags when status changes from 200 to non-200 or vice versa
                    # if website.prev_status == website.status and website.email_sent_down:
                    #     print("Resetting email_sent_down flag from True to False")
                    #     website.email_sent_down = False


                    # elif website.prev_status != 200 and website.status == 200 and website.email_sent_up:
                    #     print("Resetting email_sent_up flag from True to False")
                    #     website.email_sent_up = False
                    
                      
                    # Store status codes in the status history
                    status_history = StatusHistory(website_id=website.id, status_code=status_code)
                    db.session.add(status_history)



                    # Telegram notifications
                                        # Check if the status has changed
                    if website.prev_status != website.status:
                        # Send email notification for websites that were down and are now up
                        if website.telegram_notifications and website.prev_status != 200 and website.status == 200 and not website.telegram_sent_up:
                            message = f"The website {website.name} is now back up. URL: {website.url}"
                            send_telegram_message(website.telegram_notification_phone, message)
                            website.telegram_sent_up = True
                            website.telegram_sent_down = False

                        # Send email notification for websites that are down
                        if website.telegram_notifications and (website.prev_status == 200 or website.prev_status != 200) and website.status != 200 and not website.telegram_sent_down:
                            message = f"The website {website.name} is currently down. URL: {website.url}"
                            send_telegram_message(website.telegram_notification_phone, message)
                            website.telegram_sent_down = True  # Set flag to indicate email has been sent
                            website.telegram_sent_up = False
                            
                    print("Debugging: eda tg sent up:", website.email_sent_up)
                    print("Debugging: eda tg sent down:", website.email_sent_down)

                    # Update last_checked timestamp
                    website.last_checked = datetime.now(timezone.utc)

                    # Check SSL certificate expiry
                    try:
                        expiry_date = check_ssl_expiry(website.url)
                        if expiry_date is not None:
                            website.ssl_expiry = expiry_date
                        else:
                            website.ssl_expiry = None
                    except Exception as e:
                        logger.error(f"SSL Certificate Error: {e}")
                        traceback.print_exc()

                    # Check domain expiry
                    try:
                        domain_expiry = check_domain_expiry(website.url)
                        website.domain_expiry = domain_expiry
                    # Send email and telegram notifications if domain expiry is less than 30 days
                        if domain_expiry:
                            days_remaining = (domain_expiry - datetime.now()).days
                            if days_remaining < 30:
                                # Send email notification
                                if not website.email_sent_domain_expiry:
                                    subject = f"Domain Expiry Alert for {website.name}"
                                    body = f"The domain of {website.name} ({website.url}) will expire in {days_remaining} days."
                                    send_email(website.email_notification_email, subject, body)
                                    website.email_sent_domain_expiry = True
                                
                                # Send Telegram notification
                                if not website.telegram_sent_domain_expiry:
                                    message = f"The domain of {website.name} ({website.url}) will expire in {days_remaining} days."
                                    send_telegram_message(website.telegram_notification_phone, message)
                                    website.telegram_sent_domain_expiry = True
                                
                    except Exception as e:
                        logger.error(f"Domain Expiry Error: {e}")
                        traceback.print_exc()

                    db.session.commit()

                except requests.RequestException as e:
                    website.prev_status = website.status
                    website.status = -1
                    website.last_checked = datetime.now(timezone.utc)
                    db.session.commit()

                    # Log the error and stack trace
                    logger.error(f"Error checking website status: {e}")
                    traceback.print_exc()

                    # Here you can add additional error handling or logic if needed
                    pass  # Placeholder for future code

                # Store status codes in the status history
                status_history = StatusHistory(website_id=website.id, status_code=status_code)
                db.session.add(status_history)


# website dash for each sites
# Add a new route for the website dashboard
@app.route('/website/<int:id>/dashboard')
def website_dashboard(id):
    with app.app_context():
        website = Website.query.get_or_404(id)
        last_down_time = get_last_down_time(website.id)
        now = datetime.now()  # Get the current date and time
        return render_template('website_dashboard.html', website=website, last_down_time=last_down_time, now=now)

def get_last_down_time(website_id):
    last_down_record = StatusHistory.query.filter(StatusHistory.website_id == website_id, StatusHistory.status_code != 200).order_by(StatusHistory.timestamp.desc()).first()
    if last_down_record:
        app.logger.info(f"Found last downtime record for website {website_id}: {last_down_record.timestamp}")
        return last_down_record.timestamp
    else:
        app.logger.info(f"No last downtime record found for website {website_id}")
        return None

# chart js start
# Add a new route to fetch status history data for a specific website
@app.route('/website/<int:website_id>/status_history')
def get_status_history(website_id):
    # Fetch status history data for the specified website_id from the database
    status_history = StatusHistory.query.filter_by(website_id=website_id).order_by(StatusHistory.timestamp).all()
    
    # Extract timestamps and status codes from the status history data
    data = [{"timestamp": entry.timestamp.strftime('%Y-%m-%d %H:%M:%S'), "status_code": entry.status_code} for entry in status_history]
    
    # Return the data as JSON to the client
    return jsonify({"status_history": data})


    
# Function to send Telegram message
def send_telegram_message(chat_id, message):
    try:
        bot.send_message(chat_id, message)
    except Exception as e:
        logger.error(f"Error sending Telegram message: {e}")

# Add the necessary import at the top of your script
from apscheduler.schedulers.background import BackgroundScheduler

# Initialize the BackgroundScheduler
scheduler = BackgroundScheduler()

if __name__ == '__main__':
    with app.app_context():
        # Create all database tables if they don't exist
        db.create_all()

        # Add the check_website_status job for each website
        for website in Website.query.all():
            scheduler.add_job(check_website_status, 'interval', seconds=website.checking_interval, args=[website.id], max_instances=1)

        # Start the BackgroundScheduler
        scheduler.start()

    try:
        # Run the Flask application
        app.run(host='0.0.0.0', port=5000, debug=True)  # Change port if needed
    finally:
        # Shut down the scheduler when the application exits
        scheduler.shutdown()

