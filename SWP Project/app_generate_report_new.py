from flask import jsonify, request, session
from datetime import datetime
from sqlalchemy.orm import scoped_session, sessionmaker
from app import app, db, csrf, Incident, User, LawEnforcement

@app.route('/admin/generate_report', methods=['POST'])
@csrf.exempt
def generate_report():
    if 'admin_id' not in session:
        return jsonify({'success': False, 'error': 'Not authorized'}), 401

    try:
        filters = request.get_json()
        if not filters:
            return jsonify({'success': False, 'error': 'No filters provided'}), 400

        # Query incidents and users from main session
        query = db.session.query(Incident, User).join(User, Incident.user_id == User.id, isouter=True)

        # Apply filters on incidents and users
        if filters.get('case_type'):
            query = query.filter(Incident.crime_type == filters['case_type'])

        if filters.get('user_id'):
            query = query.filter(Incident.user_id == filters['user_id'])

        if filters.get('user_name'):
            query = query.filter(User.name.ilike(f"%{filters['user_name']}%"))

        if filters.get('date_from'):
            try:
                date_from = datetime.strptime(filters['date_from'], '%Y-%m-%d')
                query = query.filter(Incident.created_at >= date_from)
            except ValueError:
                return jsonify({'success': False, 'error': 'Invalid date_from format. Use YYYY-MM-DD'}), 400

        if filters.get('date_to'):
            try:
                date_to = datetime.strptime(filters['date_to'], '%Y-%m-%d')
                date_to = date_to.replace(hour=23, minute=59, second=59)
                query = query.filter(Incident.created_at <= date_to)
            except ValueError:
                return jsonify({'success': False, 'error': 'Invalid date_to format. Use YYYY-MM-DD'}), 400

        if filters.get('status'):
            query = query.filter(Incident.status == filters['status'])

        if filters.get('location'):
            query = query.filter(
                db.or_(
                    Incident.address.ilike(f"%{filters['location']}%"),
                    Incident.latitude.ilike(f"%{filters['location']}%"),
                    Incident.longitude.ilike(f"%{filters['location']}%")
                )
            )

        # Execute query to get incidents and users
        results = query.order_by(Incident.created_at.desc()).all()

        # If no results, return empty response
        if not results:
            return jsonify({
                'success': True,
                'message': 'No incidents found matching the criteria',
                'report_data': {
                    'incidents': [],
                    'summary': {},
                    'statistics': {}
                }
            })

        # Fetch officers from police session
        police_session = scoped_session(sessionmaker(bind=db.engines['police']))
        officers = police_session.query(LawEnforcement).all()
        officer_map = {officer.id: officer for officer in officers}

        # Prepare detailed incident data
        incidents = []
        for incident, user in results:
            officer = officer_map.get(incident.assigned_officer_id)
            incident_data = {
                'id': incident.id,
                'crime_type': incident.crime_type,
                'description': incident.description,
                'location': {
                    'latitude': incident.latitude,
                    'longitude': incident.longitude,
                    'address': incident.address
                },
                'status': incident.status,
                'created_at': incident.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'user': {
                    'id': user.id if user else None,
                    'name': user.name if user else 'Anonymous',
                    'email': user.email if user else None
                },
                'officer': {
                    'id': officer.id if officer else None,
                    'email': officer.email if officer else None,
                    'station': officer.station if officer else None,
                    'badge_number': officer.badge_number if officer else None
                }
            }
            incidents.append(incident_data)

        # Generate summary statistics
        summary = {
            'total_incidents': len(results),
            'by_status': {},
            'by_crime_type': {},
            'by_officer': {}
        }

        for incident, _ in results:
            status = incident.status or 'unknown'
            summary['by_status'][status] = summary['by_status'].get(status, 0) + 1

            crime_type = incident.crime_type or 'unknown'
            summary['by_crime_type'][crime_type] = summary['by_crime_type'].get(crime_type, 0) + 1

            officer = officer_map.get(incident.assigned_officer_id)
            if officer:
                officer_key = f"{officer.email} ({officer.station})"
                summary['by_officer'][officer_key] = summary['by_officer'].get(officer_key, 0) + 1

        resolved_count = sum(1 for i, _ in results if i.status == 'resolved')
        resolution_rate = (resolved_count / len(results)) * 100 if results else 0

        statistics = {
            'resolution_rate': round(resolution_rate, 2),
            'average_response_time': None,
            'reports_per_day': None
        }

        return jsonify({
            'success': True,
            'report_data': {
                'incidents': incidents,
                'summary': summary,
                'statistics': statistics
            }
        })

    except Exception as e:
        app.logger.error(f"Error generating report: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'An error occurred while generating the report'
        }), 500
