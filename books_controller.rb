class BooksController < ApplicationController
  before_action :set_book, only: [:show, :edit, :update, :destroy]
  # GET /books
  # GET /books.json
  def index
    @books = Book.all
    if params[:search]
      # Outputs books matching search terms, paginates to 5 items per page (as per the Basic Requirements).
      @books = Book.search(params[:search]).paginate(:page => params[:page], :per_page => 5)
      input = "#{params[:search]}"
      # BEGIN DETECTION POINT 4: String contains common SQL injection phrases.
      # Regex string (below) can be used to identify SQL injection attempts
      if ( input =~ /\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/ )
        ip_address = request.remote_ip
        event_id = "4"
        # Sends event information to Event Manager
        system("python ../IDS/logger.py -i " + ip_address + " -e " + event_id + " -n " + input)
      end
      # END DETECTION POINT 4
      # BEGIN DETECTION POINT 5: String contains XSS phrases.
      # Regex string (below) can be used to identify XSS attempts
      if ( input =~ /((\%3C)|<)[^\n]+((\%3E)|>)/ )
        ip_address = request.remote_ip
        event_id = "5"
        # Sends event information to Event Manager
        system("python ../IDS/logger.py -i " + ip_address + " -e " + event_id + " -n " + input)
      end
      # END DETECTION POINT 5
    else
      # Paginates full list of books, as per the Basic Requirements.
      @books = Book.all.paginate(:page => params[:page], :per_page => 5)
    end
  end

  # GET /books/1
  # GET /books/1.json
  def show
  end

  # GET /books/new
  def new
    authorize
    @book = Book.new
  end

  # GET /books/1/edit
  def edit
    authorize
  end

  # POST /books
  # POST /books.json
  def create
    authorize
    @book = Book.new(book_params)

    respond_to do |format|
      if @book.save
        format.html { redirect_to "http://localhost:3000/books/#{@book.id}", notice: 'Book was successfully created.' }
        format.json { render :show, status: :created, location: @book }
      else
        format.html { render :new }
        format.json { render json: @book.errors, status: :unprocessable_entity }
      end
    end
  end

  # PATCH/PUT /books/1
  # PATCH/PUT /books/1.json
  def update
    authorize
    respond_to do |format|
      if @book.update(book_params)
        format.html { redirect_to "http://localhost:3000/books/#{@book.id}", notice: 'Book was successfully updated.' }
        format.json { render :show, status: :ok, location: @book }
      else
        format.html { render :edit }
        format.json { render json: @book.errors, status: :unprocessable_entity }
      end
    end
  end

  # DELETE /books/1
  # DELETE /books/1.json
  def destroy
    @book.destroy
    respond_to do |format|
      format.html { redirect_to "http://localhost:3000/books/", notice: 'Book was successfully destroyed.' }
      format.json { head :no_content }
    end
  end

  #def borrow
  #  set_book
  #  LoansController.create(@book.id)
  #end

  private
    # Use callbacks to share common setup or constraints between actions.
    def set_book
      @book = Book.find(params[:id])
    end

    # Whitelists the specified parameters. Other parameters will not be trusted by the application.
    def book_params
      params.require(:book).permit(:title, :isbn, :publisher)
    end

end
