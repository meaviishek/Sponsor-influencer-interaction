
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
db = SQLAlchemy()
class User_login(UserMixin,db.Model):
    __tablename__ = 'user_login'
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    username = db.Column(db.String, unique=True)
    password = db.Column(db.String, unique=True)
    role=db.Column(db.String)
    flag = db.Column(db.Boolean, default=False)
    
    sponsor = db.relationship('Sponsor', uselist=False, back_populates='user')
    influencer = db.relationship('Influencer', uselist=False, back_populates='user')
    def is_active(self):
       return True

class Sponsor(db.Model):
    __tablename__ = 'sponsors'
    id = db.Column(db.Integer, db.ForeignKey('user_login.id'), primary_key=True)
    company = db.Column(db.String(120))
    industry = db.Column(db.String(120))
    budget = db.Column(db.Float)
    
    user = db.relationship('User_login', back_populates='sponsor')
    campaigns = db.relationship('Campaign', back_populates='sponsor')
    
class Influencer(db.Model):
    __tablename__ = 'influencers'
    id = db.Column(db.Integer, db.ForeignKey('user_login.id'), primary_key=True)
    name = db.Column(db.String(120))
    category = db.Column(db.String(120))
    niche = db.Column(db.String(120))
    reach = db.Column(db.Integer)
    earnings=db.Column(db.Float)
    profile_img = db.Column(db.String(120), nullable=True)
    
    user = db.relationship('User_login', back_populates='influencer')
    ad_requests = db.relationship('AdRequest', back_populates='influencer')

class Campaign(db.Model):
    __tablename__ = 'campaigns'
    id = db.Column(db.Integer, primary_key=True)
    sponsor_id = db.Column(db.Integer, db.ForeignKey('sponsors.id'), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    start_date = db.Column(db.Text, nullable=True)
    end_date = db.Column(db.Text, nullable=True)
    budget = db.Column(db.Float, nullable=True)
    visibility = db.Column(db.String(50), nullable=False, default='public') 
    goals = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), nullable=False, default='new')  
    flag = db.Column(db.Boolean, default=False)
    
    sponsor = db.relationship('Sponsor', back_populates='campaigns')
    ad_requests = db.relationship('AdRequest', back_populates='campaign')

class AdRequest(db.Model):
    __tablename__ = 'adrequests'
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaigns.id'), nullable=False)
    influencer_id = db.Column(db.Integer, db.ForeignKey('influencers.id'), nullable=False)
    messages = db.Column(db.Text, nullable=True)
    requirements = db.Column(db.Text, nullable=True)
    payment_amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), nullable=False, default='Pending')  
    by=db.Column(db.Text,nullable=False) 
    payment_status = db.Column(db.String(10), nullable=False, default='pending') 
    
     
    campaign = db.relationship('Campaign', back_populates='ad_requests')
    influencer = db.relationship('Influencer', back_populates='ad_requests')