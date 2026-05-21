import bcrypt

class User:                                                        
    def __init__(self, name, email, password):
        self.name=name
        self.email=email
        self.password=self._hashed_password(password)    #do not get plain text

    def _hashed_password(self, plan_password):             #this converts from plain password to hashed(random string mixed with bytes of the actual password, so this makes password secure and known only to that perticular user)
        salt= bcrypt.gensalt()                             #generates salt(random string)
        hashed= bcrypt.hashpw(plan_password.encode("utf-8"), salt)   # .encode("utf-8") converts string to bytes
        return hashed
    
    def valid_password(self, entered_password):
        valid= bcrypt.checkpw(entered_password.encode("utf-8"), self.password)        #checkpw takes the salt generated for actual password and scrumbles with the entered password, lets check if both matches in main.py later
        return valid
    
    
    def change_password(self,old_password, new_password):
        if self.valid_password(old_password):
            self.password=self._hashed_password(new_password)    # if old password matches allow the new password to _hashed_password method
        else:
            print("invalid password")

    def get_user(self):
       parts = self.name.split()
       first_name = parts[0]
       if len(parts) > 1:
           last_name = parts[1][0]
           return f"{first_name} {last_name}."
       return first_name      
    