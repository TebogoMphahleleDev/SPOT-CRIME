# Update the existing admin_dashboard function
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        flash("Please log in to access the admin dashboard.", "danger")
        return redirect(url_for('admin_login'))
    
    # Get all users
    users = User.query.order_by(User.created_at.desc()).all()
    
    # Get all incidents with reporter info
    incidents = db.session.query(Incident, User)\
        .join(User, Incident.user_id == User.id, isouter=True)\
        .order_by(Incident.created_at.desc())\
        .all()
    
    # Get all vouchers with user info
    vouchers = db.session.query(Voucher)\
        .options(db.joinedload(Voucher.user))\
        .order_by(Voucher.created_at.desc())\
        .all()
    
    # Get statistics for dashboard cards
    incident_count = Incident.query.count()
    user_count = User.query.count()
    pending_rewards = Voucher.query.filter_by(is_approved=False, is_redeemed=False).count()
    
    return render_template('admindashboard.html',
                     incidents=incidents,
                     users=users,
                     vouchers=vouchers,
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
