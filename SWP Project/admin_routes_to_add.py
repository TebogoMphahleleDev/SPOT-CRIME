from app import app, db
from flask import request, session, redirect, url_for, flash, render_template, jsonify
from app import User, Incident, Voucher, Admin, LawEnforcement
from sqlalchemy.orm import sessionmaker
from sqlalchemy import or_

# Update the existing admin_dashboard function
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        flash("Please log in to access the admin dashboard.", "danger")
        return redirect(url_for('admin_login'))
    
    # Get query parameters for filtering and sorting
    incident_status = request.args.get('incident_status', '')
    incident_sort = request.args.get('incident_sort', 'desc')
    incident_search = request.args.get('incident_search', '').strip()
    
    user_status = request.args.get('user_status', '')
    user_sort = request.args.get('user_sort', 'desc')
    user_search = request.args.get('user_search', '').strip()
    
    voucher_status = request.args.get('voucher_status', '')
    voucher_sort = request.args.get('voucher_sort', 'desc')
    voucher_search = request.args.get('voucher_search', '').strip()
    
    # Filter and sort users
    users_query = User.query
    if user_status:
        if user_status.lower() == 'active':
            users_query = users_query.filter(User.is_active == True)
        elif user_status.lower() == 'inactive':
            users_query = users_query.filter(User.is_active == False)
    if user_search:
        users_query = users_query.filter(
            or_(
                User.name.ilike(f"%{user_search}%"),
                User.email.ilike(f"%{user_search}%")
            )
        )
    if user_sort == 'asc':
        users_query = users_query.order_by(User.created_at.asc())
    else:
        users_query = users_query.order_by(User.created_at.desc())
    users = users_query.all()
    
    # Filter and sort incidents
    incidents_query = db.session.query(Incident, User).join(User, Incident.user_id == User.id, isouter=True)
    if incident_status:
        incidents_query = incidents_query.filter(Incident.status == incident_status)
    if incident_search:
        incidents_query = incidents_query.filter(
            or_(
                Incident.crime_type.ilike(f"%{incident_search}%"),
                Incident.address.ilike(f"%{incident_search}%"),
                User.name.ilike(f"%{incident_search}%"),
                User.email.ilike(f"%{incident_search}%")
            )
        )
    if incident_sort == 'asc':
        incidents_query = incidents_query.order_by(Incident.created_at.asc())
    else:
        incidents_query = incidents_query.order_by(Incident.created_at.desc())
    incidents = incidents_query.all()
    
    # Filter and sort vouchers
    vouchers_query = db.session.query(Voucher).options(db.joinedload(Voucher.user))
    if voucher_status:
        if voucher_status.lower() == 'pending':
            vouchers_query = vouchers_query.filter(Voucher.is_approved == False, Voucher.is_redeemed == False)
        elif voucher_status.lower() == 'approved':
            vouchers_query = vouchers_query.filter(Voucher.is_approved == True)
        elif voucher_status.lower() == 'redeemed':
            vouchers_query = vouchers_query.filter(Voucher.is_redeemed == True)
    if voucher_search:
        vouchers_query = vouchers_query.join(User).filter(
            or_(
                Voucher.reward_type.ilike(f"%{voucher_search}%"),
                User.name.ilike(f"%{voucher_search}%"),
                User.email.ilike(f"%{voucher_search}%")
            )
        )
    if voucher_sort == 'asc':
        vouchers_query = vouchers_query.order_by(Voucher.created_at.asc())
    else:
        vouchers_query = vouchers_query.order_by(Voucher.created_at.desc())
    vouchers = vouchers_query.all()
    
    # Get statistics for dashboard cards
    incident_count = Incident.query.count()
    user_count = User.query.count()
    pending_rewards = Voucher.query.filter_by(is_approved=False, is_redeemed=False).count()
    
    # Get all admins from admin database
    admin_engine = db.engines['admin']
    admin_session_maker = sessionmaker(bind=admin_engine)
    admin_session = admin_session_maker()
    try:
        admins = admin_session.query(Admin).order_by(Admin.created_at.desc()).all()
    finally:
        admin_session.close()
    
    # Get all law enforcement officers from police database
    police_engine = db.engines['police']
    police_session_maker = sessionmaker(bind=police_engine)
    police_session = police_session_maker()
    try:
        officers = police_session.query(LawEnforcement).order_by(LawEnforcement.created_at.desc()).all()
    finally:
        police_session.close()
    
    return render_template('admindashboard.html',
                     incidents=incidents,
                     users=users,
                     vouchers=vouchers,
                     admins=admins,
                     officers=officers,
                     incident_count=incident_count,
                     user_count=user_count,
                     pending_rewards=pending_rewards,
                     admin_email=session['admin_email'])

# Add these new routes after the admin_dashboard function
@app.route('/admin/create_incident', methods=['POST'])
def admin_create_incident():
    if 'admin_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    
    try:
        data = request.json
        
        # Create new incident
        new_incident = Incident(
            crime_type=data.get('crime_type'),
            description=data.get('description'),
            latitude=data.get('latitude'),
            longitude=data.get('longitude'),
            address=data.get('address'),
            status=data.get('status', 'reported')
        )
        
        # Associate with user if provided
        if 'user_id' in data and data['user_id']:
            new_incident.user_id = data['user_id']
        
        db.session.add(new_incident)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Incident created successfully',
            'incident_id': new_incident.id
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e), 'success': False, 'message': 'Error creating incident'}), 500

@app.route('/admin/get_incident/<int:id>', methods=['GET'])
def admin_get_incident(id):
    if 'admin_id' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    
    incident = Incident.query.get(id)
    if not incident:
        return jsonify({'error': 'Incident not found', 'success': False}), 404
    
    return jsonify({
        'success': True,
        'incident': {
            'id': incident.id,
            'crime_type': incident.crime_type,
            'description': incident.description,
            'latitude': incident.latitude,
            'longitude': incident.longitude,
            'address': incident.address,
            'status': incident.status,
            'user_id': incident.user_id,
            'created_at': incident.created_at.isoformat() if incident.created_at else None
        }
    })
