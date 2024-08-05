
import os
from flask import Flask,redirect,render_template,request,url_for,flash
from flask import current_app as app
from werkzeug.utils import secure_filename
from models import db,User_login,Influencer,Sponsor,Campaign,AdRequest
from flask_login import LoginManager,login_user,logout_user,current_user
from flask_login import login_required
from flask_bcrypt import Bcrypt 
from datetime import datetime
app = None
app = Flask(__name__, instance_relative_config=True)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
app.config['SECRET_KEY']='thisissecretkey'

app.config['UPLOAD_FOLDER'] = 'static/uploads/profile_images'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

db.init_app(app)


    
login_manager = LoginManager()
login_manager.init_app(app)

bcrypt = Bcrypt(app)



@login_manager.user_loader
def load_user(id):
    return User_login.query.get(int(id))


@app.route('/admin',methods=['GET','POST'])
def admin():
  if request.method == 'POST':
        username = request.form['username']
      
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        new_user = User_login(username=username, password=hashed_password, role='Admin')
        db.session.add(new_user)
        db.session.commit()

        flash('Admin registered successfully!', 'success')
        return redirect(url_for('get_login'))
  return render_template('admin.html')


@app.route('/profile',methods=['GET'])
@login_required
def profile():
   user = current_user
   profile_info = {
        'username': user.username,
       
        'role': user.role
    }

   if user.role == 'Sponsor':
        sponsor = Sponsor.query.get(user.id)
        new_requests = AdRequest.query.join(Campaign).filter(
            Campaign.sponsor_id == sponsor.id,
            (AdRequest.status == 'pending') | (AdRequest.status =='negotiation') , 
            AdRequest.by == 'Influencer'
        ).all()
        new_campaigns = Campaign.query.filter_by(sponsor_id=sponsor.id).all()
        active_campaigns =AdRequest.query.join(Campaign).join(Influencer).filter(
            Campaign.sponsor_id == sponsor.id,
            AdRequest.status == 'accepted',
            
            
        ).all()
        today = datetime.now()
        for active_campaign in active_campaigns:
            start_date = active_campaign.campaign.start_date
            end_date = active_campaign.campaign.end_date
            if isinstance(start_date, str):
                start_date = datetime.strptime(start_date, '%Y-%m-%d')
            if isinstance(end_date, str):
                end_date = datetime.strptime(end_date, '%Y-%m-%d')
            total_days = (end_date - start_date).days
            elapsed_days = (today - start_date).days
            progress_percentage = int((elapsed_days / total_days) * 100)
            active_campaign.progress = progress_percentage
            
        profile_info.update({
            'company': sponsor.company,
            'industry': sponsor.industry,
            'budget': sponsor.budget,
            'new_requests':new_requests,
            'new_campaigns': new_campaigns,
            'active_campaigns':active_campaigns,
          
        })
       
        return render_template('profile.html', profile_info=profile_info,sponsor=sponsor)
       
   elif user.role == 'Influencer':
        influencer = Influencer.query.get(user.id)
        new_requests = AdRequest.query.filter_by(influencer_id=influencer.id, 
                                                 status='pending',
                                                 by = 'Sponsor').all()
        
        active_campaigns =AdRequest.query.join(Campaign).join(Influencer).filter(
            AdRequest.influencer_id == influencer.id,
            AdRequest.status == 'accepted',
            Campaign.flag==0
            
        ).all()
        today = datetime.now()
        for active_campaign in active_campaigns:
            start_date = active_campaign.campaign.start_date
            end_date = active_campaign.campaign.end_date
            if isinstance(start_date, str):
                start_date = datetime.strptime(start_date, '%Y-%m-%d')
            if isinstance(end_date, str):
                end_date = datetime.strptime(end_date, '%Y-%m-%d')
            total_days = (end_date - start_date).days
            elapsed_days = (today - start_date).days
            progress_percentage = int((elapsed_days / total_days) * 100)
            active_campaign.progress = progress_percentage
        profile_info.update({
            'name': influencer.name,
            'category': influencer.category,
            'niche': influencer.niche,
            'reach': influencer.reach,
            'earnings':influencer.earnings,
            'profile_image':influencer.profile_img,
            'active_campaigns': active_campaigns,
            'new_requests': new_requests
        })
        return render_template('profile.html', profile_info=profile_info,influencer=influencer)
   else:
     
     

     flagged_users = User_login.query.filter_by(flag=1).all()
     flagged_campaigns = Campaign.query.filter_by(flag=1).all()
      

     return render_template('profile.html', profile_info=profile_info, flagged_users=flagged_users,flagged_campaigns=flagged_campaigns)

@app.route('/edit_sponsor_profile', methods=['POST'])
def edit_sponsor_profile():
  
    sponsor=Sponsor.query.get(current_user.id)
    company_name = request.form['company_name']
    industry = request.form['industry']
    budget = request.form['budget']
   
    sponsor.company = company_name
    sponsor.industry = industry
    sponsor.budget = budget
    
    db.session.commit()
    
   
    flash('Profile updated successfully!', 'success')
    return redirect(url_for('profile'))
  
  
@app.route('/edit_profile', methods=['POST'])
@login_required
def edit_profile():
    influencer =Influencer.query.get(current_user.id)

    name = request.form['name']
    category = request.form['category']
    niche = request.form['niche']
    reach = request.form['reach']

    influencer.name = name
    influencer.category = category
    influencer.niche = niche
    influencer.reach = reach

  
    if 'profile_image' in request.files:
        profile_image = request.files['profile_image']
        if profile_image.filename != '':
            filename = secure_filename(profile_image.filename)
            profile_image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            influencer.profile_image = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    db.session.commit()

    flash('Profile updated successfully', 'success')
    return redirect(url_for('profile'))

@app.route('/pay/<int:ad_request_id>', methods=['POST'])
def pay(ad_request_id):
    ad_request = AdRequest.query.get_or_404(ad_request_id)
    
    if ad_request.status == 'accepted':
       influencer =Influencer.query.get(ad_request.influencer_id)
       if influencer.earnings is None:
          influencer.earnings = 0
       influencer.earnings += ad_request.payment_amount
       ad_request.payment_status = 'paid'
       db.session.commit()
       flash('Payment successful for ad request ID: {}'.format(ad_request.id), 'success')
    else:
        flash('Ad request must be accepted before payment.', 'error')
    return redirect(url_for('profile'))

@app.route('/remove_flag', methods=['POST'])
@login_required
def remove_flag():
     action = request.form.get('action')
     entity_id = request.form.get('entity_id')
     entity_type = request.form.get('entity_type')

     if entity_type == 'user':
            user = User_login.query.get(entity_id)
            if user:
                user.flag= 1 if action == 'flag' else 0
                db.session.commit()
     elif entity_type == 'campaign':
            campaign = Campaign.query.get(entity_id)
            if campaign:
                campaign.flag = 1 if action == 'flag' else 0
                db.session.commit()

     return redirect(url_for('profile'))



@app.route('/',methods=['GET','POST'])
def get_login():
  if request.method == "POST":
      
      username=request.form['username']
      password=request.form['password']
      user=User_login.query.filter_by(username=username).first()
      if user.flag:
        flash('Your account has been flagged. Please contact support.', 'error')
        return redirect(url_for('get_login'))
      if user:
        if bcrypt.check_password_hash(user.password,password):
            login_user(user)
            return redirect(url_for('profile'))
        else:
          flash('Invalid password','error')
          return render_template('login.html')
      else:
        flash('Invalid username','error')
        

  return render_template('login.html')


@app.route('/campaign/<int:campaign_id>/view', methods=['GET'])
@login_required
def view_campaign(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    return render_template('view_campaign.html', campaign=campaign)
  

@app.route('/ad_request/<int:ad_id>/accept', methods=['POST'])
@login_required
def accept_ad_request(ad_id):
    ad_request = AdRequest.query.get(ad_id)

    if not ad_request:
    
        return redirect(url_for('profile'))
    campaign = ad_request.campaign
    if (current_user.role == 'Sponsor' and campaign.sponsor.id != current_user.id) or (current_user.role == 'Influencer' and ad_request.influencer.id != current_user.id):
        return redirect(url_for('profile'))
    if ad_request.messages:
        ad_request.payment_amount=extract_payment_from_message(ad_request.messages)
    ad_request.status = 'accepted'  
    db.session.commit()
    
   
    return redirect(url_for('profile'))

def extract_payment_from_message(message):
    import re
    match = re.search(r'\$?(\d+(\.\d{2})?)', message)
    if match:
        return float(match.group(1))
    return None

@app.route('/ad_request/<int:ad_id>/reject', methods=['POST'])
@login_required
def reject_ad_request(ad_id):
    ad_request = AdRequest.query.get(ad_id)
    if not ad_request:
    
        return redirect(url_for('profile'))
    campaign = ad_request.campaign
    if (current_user.role == 'Sponsor' and campaign.sponsor.id != current_user.id) or (current_user.role == 'Influencer' and ad_request.influencer.id != current_user.id):
        return redirect(url_for('profile'))
    
    ad_request.status = 'rejected'
    db.session.commit()

@app.route('/influencer_reg',methods=['GET','POST'])
def influencer_reg():
  if request.method == "POST":
    
    username=request.form['username']
    name=request.form['name']
    category=request.form['category']
    niche=request.form['niche']
    reach=request.form['reach']
    password=request.form['password']
    file = request.files.get('file')
    
    
    if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])
            
        
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            
            relative_file_path = os.path.join('uploads', 'profile_images', filename).replace('\\', '/')
    else:
            flash('Invalid file type!', 'error')
            return redirect(url_for('influencer_reg'))
          
          
    user=User_login.query.filter_by(username=username).first()
    if user:
      flash('Username already exists', 'error')
      return redirect(url_for('influencer_reg'))
    
    hash_pass = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user=User_login(username=username,password=hash_pass,role="Influencer")
    db.session.add(new_user)
    db.session.commit()
    
    new_influencer=Influencer(id=new_user.id,name=name,category=category,niche=niche,reach=reach,profile_img=relative_file_path)
    db.session.add(new_influencer)
    db.session.commit()
    
    flash('Influencer registered successfully!', 'success')
    return redirect(url_for('get_login'))
    
  
  return render_template('influencer_reg.html')

@app.route('/sponsor_reg',methods=['GET','POST'])
def sponsor_reg():
  if request.method == "POST":
    username=request.form['username']
    company=request.form['company']
    industry=request.form['industry']
    budget=request.form['budget']
  
    password=request.form['password']
    special=['@','#','$']
    if len(password)< 6 and not any(c in special for c in password ) :
      flash('Password must be at least 6 characters long! and special  char like @,#,$ ', 'error')

    user=User_login.query.filter_by(username=username).first()
    if user:
      flash('Username already exists', 'error')
      return redirect(url_for('sponsor_reg'))
    
    hash_pass = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user=User_login(username=username,password=hash_pass,role="Sponsor")
    db.session.add(new_user)
    db.session.commit()
    
    new_sponsor=Sponsor(id=new_user.id,company=company,industry=industry,budget=budget)
    db.session.add(new_sponsor)
    db.session.commit()
    
    flash('sponsor registered successfully!', 'success')
    return redirect('/')
    
  
  return render_template('sponsor_reg.html')



@app.route('/logout',methods=['GET'])
def logout():
  logout_user()
  return redirect('/')

@app.route('/campaign/<string:form>',methods=['GET','POST'])
def campaignandrequest(form):
  if request.method == 'POST':
    if form == 'newcampaign':
      title=request.form['name']  
      description=request.form['description']
      start_date=request.form['start_date']
      end_date = request.form['end_date']
      budget = request.form['budget']
      visibility = request.form['visibility']
      goals = request.form['goals']
      new_campaign = Campaign(
            sponsor_id=current_user.sponsor.id,
            name=title,
            description=description,
            start_date=start_date,
            end_date=end_date,
            budget=budget,
            visibility=visibility,
            goals=goals
        )
    
    
  
      db.session.add(new_campaign)
      db.session.commit()
      flash('new campaign added', 'success')
    elif form=='adrequest':
      campaign_id=request.form['campaign_id']
      influencer_id=request.form['influencer_id']
      
      payment_amount=request.form['payment_amount']
      requirements=request.form['requirements']
      new_ad_request = AdRequest(
        campaign_id=campaign_id,
        influencer_id=influencer_id,
       
       
        requirements=requirements,
        payment_amount=payment_amount,
        status='pending',
        by='Sponsor'
        
      )
      db.session.add(new_ad_request)
      db.session.commit()
      flash('Ad Request sent', 'success')
      
  return redirect(url_for('addcampaign'))
  

@app.route('/campaign',methods=['GET','POST'])
def addcampaign():
  if current_user.role == 'Sponsor':
        user_details = Sponsor.query.filter_by(id=current_user.id).first()
        influencers=Influencer.query.all()
  elif current_user.role == 'Influencer':
        user_details = Influencer.query.filter_by(id=current_user.id).first()
      
  campaigns = Campaign.query.filter_by(sponsor_id=current_user.sponsor.id).all()
  return render_template('addcampaign.html', user=current_user, user_details=user_details,campaigns=campaigns,influencers=influencers)





@app.route('/find',methods=['GET','POST'])
def find():
  if current_user.role == 'Influencer':
      
        campaigns = []
        requested=[]
        if request.method == 'POST':
            search_term = request.form.get('search_term', '').strip()
            campaigns = Campaign.query.filter(Campaign.name.ilike(f'%{search_term}%'),Campaign.flag == 0).all()
        
        influencer = Influencer.query.filter_by(id=current_user.id).first()
        if influencer:
          requested_campaigns = AdRequest.query.filter_by(influencer_id=influencer.id).all()
          requested = [req.campaign_id for req in requested_campaigns]
        return render_template('find.html',user=current_user, campaigns=campaigns,requested=requested)       

  elif current_user.role == 'Sponsor':
    
        influencers = []

        if request.method == 'POST':
           search_term = request.form.get('search_term', '').strip()
           influencers = Influencer.query.join(User_login).filter(User_login.username.ilike(f'%{search_term}%'),User_login.flag==0).all()
           
           
    
        return render_template('find.html',user=current_user, influencers=influencers, campaigns=None)
  else:
    campaigns = []
    influencers = []
    if request.method == 'POST':
           search_term = request.form.get('search_term', '').strip()
           influencers = Influencer.query.join(User_login).filter(User_login.username.ilike(f'%{search_term}%')).all()
           campaigns = Campaign.query.filter(Campaign.name.ilike(f'%{search_term}%')).all()
    return render_template('find.html',user=current_user, influencers=influencers, campaigns=campaigns)
     
@app.route('/flag_entity', methods=['POST'])
@login_required
def flag_entity():
    
    action = request.form.get('action')
    entity_id = request.form.get('entity_id')
    entity_type = request.form.get('entity_type')

    if entity_type == 'user':
        user = User_login.query.get(entity_id)
        if user:
            user.flag= 1 if action == 'flag' else 0
            db.session.commit()
    elif entity_type == 'campaign':
        campaign = Campaign.query.get(entity_id)
        if campaign:
            campaign.flag = 1 if action == 'flag' else 0
            db.session.commit()

    return redirect(url_for('find'))



@app.route('/ad_request', methods=['POST'])
@login_required
def create_ad_request():
    campaign_id = request.form.get('campaign_id')
    campaign = Campaign.query.get(campaign_id)
    new_price = request.form.get('new_price')
    influencer = Influencer.query.filter_by(id=current_user.id).first()
    if not influencer:
      
        return redirect(url_for('find'))
    if int(new_price) > 0:
        new_ad_request = AdRequest(
        campaign_id=campaign_id,
        influencer_id=influencer.id,
        messages=f"Proposed new price: ${new_price}",
        status='negotiation',
        by='Influencer'
    )
    else:    
       new_ad_request = AdRequest(
        campaign_id=campaign_id,
        influencer_id=influencer.id,
        status='pending',
        by='Influencer'
    )
    db.session.add(new_ad_request)
    db.session.commit()
    flash('Ad Request sent', 'success')
    return redirect(url_for('find'))








@app.route('/stats',methods=['GET'])
def stats():
  if current_user.role == 'Sponsor':
        user_details = Sponsor.query.filter_by(id=current_user.id).first()
  elif current_user.role == 'Influencer':
        user_details = Influencer.query.filter_by(id=current_user.id).first()

  
  user = current_user
  if user.role == 'Sponsor':
        
    sponsor = Sponsor.query.filter_by(id=user.id).first()
    if not sponsor:
        flash('Sponsor profile not found!', 'error')
        return redirect(url_for('index'))
      
    campaigns = Campaign.query.filter_by(sponsor_id=sponsor.id).all()
    
    
    total_campaigns = len(campaigns)
    total_budget = sum(campaign.budget for campaign in campaigns)
    
   
    ad_requests = AdRequest.query.join(Campaign).filter(Campaign.sponsor_id == sponsor.id).all()
    
 
    total_requests = len(ad_requests)
    accepted_requests = len([request for request in ad_requests if request.status == 'accepted'])
    rejected_requests = len([request for request in ad_requests if request.status == 'rejected'])
    pending_requests = len([request for request in ad_requests if request.status == 'pending'])
    negotiation_requests = len([request for request in ad_requests if request.status == 'negotiation'])

    stats_data = {
        'total_campaigns': total_campaigns,
        'total_budget': total_budget,
        'total_requests': total_requests,
        'accepted_requests': accepted_requests,
        'rejected_requests': rejected_requests,
        'pending_requests': pending_requests,
        'negotiation_requests': negotiation_requests
    }
   
    campaign_names = [campaign.name for campaign in campaigns]
    budgets = [campaign.budget for campaign in campaigns]
    return render_template('stats.html', user=current_user, user_details=user_details,stats_data=stats_data,campaign_names=campaign_names,budgets=budgets)
  elif user.role == 'Influencer':
    
   
    campaigns = AdRequest.query.join(Campaign).filter(Campaign.flag == False, AdRequest.influencer_id == current_user.id, AdRequest.status == 'accepted',AdRequest.payment_status=='paid').all()
    
    labels = [camp.campaign.name for camp in campaigns]
    earnings = [campaign.payment_amount for campaign in campaigns]
    
    total_campaigns = Campaign.query.count()
    active_campaigns = Campaign.query.join(AdRequest).filter(Campaign.flag == False, AdRequest.influencer_id == current_user.id, AdRequest.status == 'accepted').count()
    total_earnings = db.session.query(db.func.sum(AdRequest.payment_amount)).filter_by(influencer_id=current_user.id, status='accepted',payment_status='paid').scalar()
    total_earnings = total_earnings if total_earnings else 0
    accepted_ad_requests = AdRequest.query.filter_by(influencer_id=current_user.id, status='accepted').count()
    rejected_ad_requests = AdRequest.query.filter_by(influencer_id=current_user.id, status='rejected').count()
    pending_ad_requests = AdRequest.query.filter_by(influencer_id=current_user.id, status='pending').count()

    stats_data = {
        "total_campaigns": total_campaigns,
        "active_campaigns": active_campaigns,
        "total_earnings": total_earnings,
        "accepted_ad_requests": accepted_ad_requests,
        "rejected_ad_requests": rejected_ad_requests,
        "pending_ad_requests": pending_ad_requests
    }

    return render_template('stats.html',user=current_user, stats_data=stats_data,labels=labels,earnings=earnings)
  else:
    total_influencers = User_login.query.filter_by(role='Influencer').count()
    total_sponsors = User_login.query.filter_by(role='Sponsor').count()
    total_campaigns = Campaign.query.count()
    active_campaigns = Campaign.query.filter_by(flag=0).count()
    flagged_campaigns = Campaign.query.filter_by(flag=1).count()
    total_ad_requests = AdRequest.query.count()
    accepted_ad_requests = AdRequest.query.filter_by(status='accepted').count()
    rejected_ad_requests = AdRequest.query.filter_by(status='rejected').count()
    pending_ad_requests = AdRequest.query.filter_by(status='pending').count()

    return render_template('stats.html',user=current_user, total_influencers=total_influencers, total_sponsors=total_sponsors,
                           total_campaigns=total_campaigns, active_campaigns=active_campaigns,
                           flagged_campaigns=flagged_campaigns, total_ad_requests=total_ad_requests,
                           accepted_ad_requests=accepted_ad_requests, rejected_ad_requests=rejected_ad_requests,
                           pending_ad_requests=pending_ad_requests)
  
   
   
   
if __name__ == '__main__':
  app.run(debug=True)