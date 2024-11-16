#!/usr/bin/env python3

from flask import request, session, jsonify, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json()
        print(data)
        username = data.get('username', None)
        password = data['password']
        image_url = data['image_url']
        bio = data['bio']

        if not username:
            print("NO username in data!")#
            return make_response(jsonify({'errors': 'Missing username.'}), 422)

        new_user = User(username=username, image_url=image_url, bio=bio)
        print(new_user)
        try:
            new_user.password_hash = password 

            db.session.add(new_user)
            db.session.commit()

            session['user_id'] = new_user.id

            return make_response(new_user.to_dict(), 201)

        except IntegrityError:
            db.session.rollback()
            print("IntegrityError: User Already exists.")
            return make_response(jsonify({'errors': 'Username already taken.'}), 422)

        except Exception as e:
            db.session.rollback()
            return make_response(jsonify({'errors': f"{str(e)}"}), 422)


class CheckSession(Resource):
    def get(self):
        user_id = session['user_id']
        print(f"user id: {user_id}")
        if user_id:
            user = User.query.filter(User.id == user_id).first()
            return make_response(user.to_dict(), 200)
        else:
            return make_response(jsonify({"error" : "You are not logged in."}), 401)

class Login(Resource):
    def post(self):
        data = request.get_json()
        print(data)
        username = data.get('username', None)
        password = data['password']

        user = User.query.filter(User.username == username).first()
        print(user)
        if not user:
            return make_response(jsonify({"error" : "invalid username"}), 401)

        if user.authenticate(password):
            session['user_id'] = user.id

            return make_response(user.to_dict(), 200)

        return make_response(jsonify({"error" : "invalid username or password."}), 401)
            


class Logout(Resource):
    def delete(self):
        user_id = session['user_id']
        if user_id:
            session['user_id'] = None

            return make_response({}, 204)
        else:
            return make_response(jsonify({"error" : 'Cannot logout because you are already logged out'}), 401)
        
class RecipeIndex(Resource):
    def get(self):
        user_id = session['user_id']

        if user_id:
            user = User.query.filter(User.id == user_id).first()

            recipes = [recipe.to_dict() for recipe in Recipe.query.all() if recipe.user_id == user.id]

            return make_response(jsonify(recipes), 200)

        return make_response(jsonify({"error": "You are not logged in"}), 401)

    def post(self):
        user_id = session['user_id']

        if user_id:
            data = request.get_json()
            print(data)
            title = data.get('title', None)
            instructions = data.get('instructions', None)
            minutes_to_complete = data['minutes_to_complete']

            if not title or not instructions:
                print("invalid title or instructions")
                return make_response(jsonify({"error" : "invalid title or instructions"}), 422)

            try:
                new_recipe = Recipe(title=title, instructions=instructions, minutes_to_complete=minutes_to_complete)
                print(f"The new recipe created: {new_recipe}")
                new_recipe.user_id = user_id
                
                db.session.add(new_recipe)
                db.session.commit()

                user = User.query.filter(User.id == new_recipe.user_id).first()
                print(f"User matching new_recipe.user_id {user}")

                if not user:
                    print("no user matching new_recipe.user_id found.")
                    return make_response(jsonify({"error" : "could not get user from database"}), 422)

                new_recipe_dictionary = new_recipe.to_dict()
                new_recipe_dictionary["user"] = user.to_dict()
                print(f"new recipe dictionary: {new_recipe_dictionary}")

                return make_response(jsonify(new_recipe_dictionary), 201)
            
            except IntegrityError:
                db.session.rollback()
                print("IntegrityError: Title and Instructions cannot be empty")
                return make_response(jsonify({'errors': 'Title and Instructions cannot be empty.'}), 422)

            except Exception as e:
                db.session.rollback()
                return make_response(jsonify({'errors': f"{str(e)}"}), 422)

        else:
            print("no user_id value in session.")
            return make_response(jsonify({"error" : "You are not logged in."}), 401)
        


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)