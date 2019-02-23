#! /usr/bin/env python3

from flask import (Flask,
                   render_template,
                   request,
                   redirect,
                   jsonify,
                   url_for)

from functools import wraps
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from models import Base, Category, Item, User

# Imports for anit forgery state token
from flask import session as login_session
import random
import string
import os


# Imports for setting up OAuth
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog Application"

# Connect to Database and create database session
engine = create_engine('sqlite:///itemCatalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

# Operations on OAuth2


@app.route('/login')
def showLogin():
    ''' Create a state token to prevent request forgery.
        Store it in the session for later validation

    Returns:
        to login page
    '''
    state = ''.join(random.choice(string.ascii_uppercase +
                                  string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state, CLIENT_ID = CLIENT_ID)

# Handle google login


@app.route('/gconnect', methods=['POST'])
def gconnect():
    ''' Handle google login transaction


    Returns:
        username login session when login is successful
        error response if error occured
    '''

    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data.get('name', 'Stranger :) ')
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # see if user exists, if it does not exist, create a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    return login_session['username']


# Handle google logout
@app.route('/gdisconnect')
def gdisconnect():
    ''' Handle google disconnect transaction


    Returns:
        to main page when disconnect is successful
        error response if error ocurred
    '''

    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        # login_session.pop('username', None)
        login_session.clear()
        return redirect(url_for('showCategories'))
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


def createUser(login_session):
    ''' Creates a new user in the database

    Args:
        login_session: session object with user data.

    Returns:
        user.id: generated distinct integer value identifying the newly created
    '''
    session = DBSession()
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    ''' Collect user information from the database

    Args:
        user_id: user id in the database

    Returns:
       user: user object associated with the user id provided as arg
    '''
    session = DBSession()
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    ''' Collect user id from the database

    Args:
        email: user email address

    Returns:
        user.id: generated distinct integer value identifying the newly created
        None: when email is not found
    '''
    try:
        session = DBSession()
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# Operations on Category


def login_required(f):
    ''' Check whether user is signed in

    Args:
        f: the function we are wrapping

    Returns:
        decorated_function: the function we are wrapping when user is signed in
        redirect: redirect to login page when user is not signed in
    '''
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in login_session:
            return redirect(url_for('showLogin'))
        return f(*args, **kwargs)
    return decorated_function

# Show all categories


@app.route('/')
@app.route('/category/')
def showCategories():
    ''' Show all categories available in the database


    Returns:
        Page that shows all the categories
    '''
    session = DBSession()
    categories = session.query(Category).order_by(asc(Category.name))
    if 'username' not in login_session:
        return render_template('publicCategory.html', categories=categories)
    else:
        return render_template('category.html', categories=categories)


# Create a new category
@app.route('/category/new/', methods=['GET', 'POST'])
@login_required
def newCategory():
    ''' Create new category in the database


    Returns:
        on GET: page to create a new category
        on POST: redirect to main page after category is created.
        to loging page when user is not signed in
    '''
    session = DBSession()
    if request.method == 'POST':
        newCategory = Category(
            name=request.form['name'], user_id=login_session['user_id'])
        session.add(newCategory)
        session.commit()
        return redirect(url_for('showCategories'))
    else:
        return render_template('newCategory.html')


# Edit a Category
@app.route('/category/<int:category_id>/edit/', methods=['GET', 'POST'])
@login_required
def editCategory(category_id):
    ''' Edit specific category in the database


    Returns:
        on GET: page to edit category
        on POST: redirect to main page after category is created.
        to loging page when user is not signed in
    '''
    session = DBSession()
    editedCategory = session.query(Category).filter_by(id=category_id).one()
    if editedCategory.user_id != login_session['user_id']:
        return redirect(url_for('showItem', category_id=category_id))
    if request.method == 'POST':
        if request.form['name']:
            editedCategory.name = request.form['name']
            session.add(editedCategory)
            session.commit()
            return redirect(url_for('showCategories'))
    else:
        return render_template('editCategory.html', category=editedCategory)


# Delete a Category
@app.route('/category/<int:category_id>/delete/', methods=['GET', 'POST'])
@login_required
def deleteCategory(category_id):
    ''' Delete category from the database


    Returns:
        on GET: page to delete category
        on POST: redirect to main page after category deleted.
        to loging page when user is not signed in
    '''
    session = DBSession()
    categoryToDelete = session.query(Category).filter_by(id=category_id).one()
    if categoryToDelete.user_id != login_session['user_id']:
        return redirect(url_for('showItem', category_id=category_id))
    if request.method == 'POST':
        session.delete(categoryToDelete)
        session.commit()
        return redirect(url_for('showCategories'))
    else:
        return render_template('deleteCategory.html',
                               category=categoryToDelete)


# Operations on Items

# Show a category items
@app.route('/category/<int:category_id>/')
def showItem(category_id):
    ''' Show all items available under specific category


    Returns:
        To public items page when user is not signed in
        To main items page when user is signed in
    '''
    session = DBSession()
    category = session.query(Category).filter_by(id=category_id).one()
    creator = getUserInfo(category.user_id)
    items = session.query(Item).filter_by(category_id=category_id).all()
    if 'username' not in login_session:
        return render_template('publicItems.html',
                               items=items,
                               category=category,
                               creator=creator)
    else:
        return render_template('items.html',
                               items=items,
                               category=category,
                               creator=creator)


# Show an item details
@app.route('/category/<int:category_id>/<int:item_id>')
def showItemDetails(category_id, item_id):
    ''' Show details for specific item


    Returns:
        Show item details page
    '''
    session = DBSession()
    item = session.query(Item).filter_by(id=item_id).one()
    return render_template('showItem.html', item=item)


# Create a new item
@app.route('/category/<int:category_id>/new/', methods=['GET', 'POST'])
@login_required
def newItem(category_id):
    ''' Create new item in the database


    Returns:
        on GET: page to create a new item
        on POST: redirect to main page after item is created.
        to loging page when user is not signed in
    '''
    session = DBSession()
    category = session.query(Category).filter_by(id=category_id).one()
    if request.method == 'POST':
        image_path =\
            'http://canamerica.adsfreevideos.com/upload/noimage.jpg'
        if request.form["image"]:
            image_path = request.form["image"]
        newItem = Item(name=request.form['name'],
                       description=request.form['description'],
                       image=image_path,
                       category_id=category_id,
                       user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        return redirect(url_for('showItem', category_id=category_id))
    else:
        return render_template('newItem.html')

# Edit an item


@app.route('/category/<int:category_id>/<int:item_id>/edit',
           methods=['GET', 'POST'])
@login_required
def editItem(category_id, item_id):
    ''' Edit item in the database


    Returns:
        on GET: page to edit an item
        on POST: redirect to main page after item is edited.
        to loging page when user is not signed in
    '''
    session = DBSession()
    editedItem = session.query(Item).filter_by(id=item_id).one()
    if editedItem.user_id != login_session['user_id']:
        return redirect(url_for('showItem', category_id=category_id))
    if request.method == 'POST':
        image_path =\
            'http://canamerica.adsfreevideos.com/upload/noimage.jpg'
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['image']:
            editedItem.image = request.form['image']
        else:
            editedItem.image = image_path
        session.add(editedItem)
        session.commit()
        return redirect(url_for('showItem', category_id=category_id))
    else:
        return render_template('editItem.html', item=editedItem)


# Delete an item
@app.route('/category/<int:category_id>/<int:item_id>/delete',
           methods=['GET', 'POST'])
@login_required
def deleteItem(category_id, item_id):
    ''' Delete item from the database


    Returns:
        on GET: page to delete item
        on POST: redirect to main page after item is deleted.
        to loging page when user is not signed in
    '''
    session = DBSession()
    itemToDelete = session.query(Item).filter_by(id=item_id).one()
    if itemToDelete.user_id != login_session['user_id']:
        return redirect(url_for('showItem', category_id=category_id))
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        return redirect(url_for('showItem', category_id=category_id))
    else:
        return render_template('deleteItem.html', item=itemToDelete)


# API Operations

# JSON APIs to view all categories
@app.route('/api/v<int:version>/category')
def categoryJSON(version):
    ''' Create JSON end-point to show all categories


    Returns:
        JSON end-point with all the categories
        JSON end-point with error when version is invalid
    '''
    if version == 1:
        session = DBSession()
        category = session.query(Category).all()
        return jsonify(Category=[i.serialize for i in category])
    else:
        return jsonify({"error": "Invalid version number"})

# JSON APIs to view all items


@app.route('/api/v<int:version>/items')
def itemJSON(version):
    ''' Create JSON end-point to show all items


    Returns:
        JSON end-point with all the items
        JSON end-point with error when version is invalid
    '''
    if version == 1:
        session = DBSession()
        category = session.query(Item).all()
        return jsonify(Items=[i.serialize for i in category])
    else:
        return jsonify({"error": "Invalid version number"})

# JSON APIs to view items of specific category


@app.route('/api/v<int:version>/category/<int:category_id>')
def categoryItemsJSON(version, category_id):
    ''' Create JSON end-point to show all items in specific category


    Returns:
        JSON end-point with all the items in specific category
        JSON end-point with error when version is invalid
    '''
    if version == 1:
        session = DBSession()
        items = session.query(Item).filter_by(category_id=category_id).all()
        return jsonify(Items=[i.serialize for i in items])
    else:
        return jsonify({"error": "Invalid version number"})


# JSON APIs to view specific item information
@app.route('/api/v<int:version>/category/<int:category_id>/item/<int:item_id>')
def iTemsJSON(version, category_id, item_id):
    ''' Create JSON end-point with specific item details


    Returns:
        JSON end-point with specific item details
        JSON end-point with error when version is invalid
    '''
    if version == 1:
        session = DBSession()
        item = session.query(Item).filter_by(id=item_id).one()
        return jsonify(item.serialize)
    else:
        return jsonify({"error": "Invalid version number"})


if __name__ == '__main__':
    app.secret_key = os.urandom(16)
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
