from flask import render_template, request, flash, redirect, url_for
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Message

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = generate_token(email)
            reset_url = url_for('reset_password_token', token=token, _external=True)
            
            msg = Message('Password Reset Request',
                        recipients=[email])
            msg.body = f'''To reset your password, visit:
{reset_url}

If you didn't request this, please ignore this email.'''
            try:
                mail.send(msg)
                flash('Password reset link sent if email exists', 'success')
            except Exception as e:
                flash('Failed to send reset email', 'danger')
                app.logger.error(f"Password reset error: {str(e)}")
        else:
            flash('Password reset link sent if email exists', 'success')
        
        return redirect(url_for('login'))
    
    return render_template('reset_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    email = confirm_token(token)
    if not email:
        flash('Invalid/expired reset link', 'danger')
        return redirect(url_for('reset_password_request'))
    
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('reset_password_request'))
    
    if request.method == 'POST':
        password = request.form['password']
        confirm = request.form['confirm_password']
        
        if password != confirm:
            flash('Passwords must match', 'danger')
            return redirect(url_for('reset_password_token', token=token))
            
        user.password = bcrypt.generate_password_hash(password).decode('utf-8')
        db.session.commit()
        flash('Password updated successfully!', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password_token.html', token=token)

def generate_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
        return email
    except Exception:
        return False
