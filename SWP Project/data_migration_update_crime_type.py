from app import app, db, Incident, IncidentType

def update_crime_type_names():
    with app.app_context():
        incidents = Incident.query.all()
        updated_count = 0
        for incident in incidents:
            if incident.crime_type and incident.crime_type.isdigit():
                incident_type = IncidentType.query.get(int(incident.crime_type))
                if incident_type:
                    incident.crime_type = incident_type.name
                    updated_count += 1
        db.session.commit()
        print(f"Updated {updated_count} incidents with numeric crime_type to names.")

if __name__ == "__main__":
    update_crime_type_names()
