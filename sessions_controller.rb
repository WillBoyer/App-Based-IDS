class SessionsController < ApplicationController
  def new
  end

  # A session is created when a librarian signs in.
  def create
    # Retrieves librarians login details based on email address.
    librarian = Librarian.find_by(email: params[:session][:email].downcase)
    if librarian && librarian.authenticate(params[:session][:password])
      # Sign the librarian in and redirect to the librarian's show page.
      sign_in(librarian)
      current_user
      respond_to do |format|
        format.html { redirect_to "http://localhost:3000/librarians/#{librarian.id}" , notice: 'You have successfully signed in!.' }
      end
    else
      flash[:notice] ='Invalid login/password combination'
      render 'new'
      # Logs IP address
      email = params[:session][:email]
      input = 'none'
      ip_address = request.remote_ip
      event_id = '0'
      # BEGIN DETECTION POINT 3: failed login attempts for common usernames.
      if File.readlines("common_usernames.txt").grep(/#{email}/).size > 0
        event_id = '3'
      # END DETECTION POINT 3
      # BEGIN DETECTION POINT 4: String contains common SQL injection phrases.
      elsif email =~ /\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/
        event_id = "4"
        input = email
      # END DETECTION POINT 4
      # BEGIN DETECTION POINT 1: Use of multiple incorrect passwords.
      else
        # If username exists
        if librarian.present?
          event_id = '1'
      # END DETECTION POINT 1
      # BEGIN DETECTION POINT 2: Failed login attempts for multiple usernames
        else
          event_id = '2'
        end
      end
      # END DETECTION POINT 2
      # Sends event information to Event Manager
      system("python ../IDS/logger.py -i " + ip_address + " -e " + event_id + " -n " + input)

    end

  end

  # Destroys session when a librarian logs out.
  def destroy
    signout
    respond_to do |format|
      format.html { redirect_to "http://localhost:3000/" , notice: 'You have successfully signed out.'}
    end
  end

end
