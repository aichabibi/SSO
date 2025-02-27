import boto3
import time
from botocore.exceptions import ClientError
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_bcrypt import Bcrypt
from flask_session import Session
 
# Initialisation de Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = 'super_secret_key'
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)
 
bcrypt = Bcrypt(app)
 
# Configuration AWS DynamoDB
ACCESS_KEY_ID = "AKIA46ZDFBCVARZQ24UM"
ACCESS_SECRET_KEY = "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"
 
 
 
dynamodb = boto3.resource(
   'dynamodb',
   aws_access_key_id=ACCESS_KEY_ID,
   aws_secret_access_key=ACCESS_SECRET_KEY,
   region_name='eu-west-3'
)
 
TABLE_NAME = "Users"
 
# Fonction pour créer la table si elle n'existe pas
def create_dynamodb_table():
    existing_tables = list(dynamodb.tables.all())
 
    if TABLE_NAME not in [table.name for table in existing_tables]:
        print("📌 La table n'existe pas. Création en cours...")
 
        table = dynamodb.create_table(
            TableName=TABLE_NAME,
            KeySchema=[
                {'AttributeName': 'username', 'KeyType': 'HASH'}  # Clé primaire
            ],
            AttributeDefinitions=[
                {'AttributeName': 'username', 'AttributeType': 'S'}  # Type String
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            }
        )
 
        # Attendre la création de la table
        table.wait_until_exists()
        print("✅ Table créée avec succès !")
 
# Vérifier et créer la table au démarrage
create_dynamodb_table()
users_table = dynamodb.Table(TABLE_NAME)
 
# Page d'accueil
@app.route('/')
def index():
    return render_template('index.html')
 
# Page d'inscription
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
 
        if not username or not password:
            return "Tous les champs sont obligatoires", 400
 
        try:
            response = users_table.get_item(Key={'username': username})
            if 'Item' in response:
                return "Nom d'utilisateur déjà pris", 400
        except ClientError as e:
            return f"Erreur DynamoDB : {str(e)}", 500
 
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
 
        users_table.put_item(Item={'username': username, 'password': hashed_password})
        return redirect(url_for('login'))
 
    return render_template('register.html')
 
# Page de connexion
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
 
        try:
            response = users_table.get_item(Key={'username': username})
            user = response.get('Item')
 
            if not user or not bcrypt.check_password_hash(user['password'], password):
                return "Identifiants incorrects", 401
 
            session['user'] = username
            return redirect(url_for('dashboard'))
 
        except ClientError as e:
            return f"Erreur DynamoDB : {str(e)}", 500
 
    return render_template('login.html')
 
# Page après connexion
@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        return render_template('dashboard.html', user=session['user'])
    return redirect(url_for('login'))
 
# Déconnexion
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))
 
if __name__ == '__main__':
    app.run(debug=True)