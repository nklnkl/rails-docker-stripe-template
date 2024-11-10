class UsersController < ApplicationController
  before_action :authenticate_user!

  def show
    render json: current_user, only: [
      :id,
      :email,
      :sign_in_count,
      :current_sign_in_at,
      :last_sign_in_at,
      :current_sign_in_ip,
      :last_sign_in_ip
    ]
  end

  def jwt
    render json: current_user.jwt(params[:jti])
  end

  def active_jwts
    render json: current_user.active_jwts
  end

  def delete_jwt
    current_user.delete_jwt(params[:jti])
  end

  def delete_all_jwts
    current_user.delete_all_jwts
  end

  # GET /users/has_active_subscription
  def has_active_subscription
    if current_user.has_active_subscription?
      head :ok
    else
      head :payment_required
    end
  end

  # POST /users/create_checkout_session_for_subscription
  #
  # @param price_id [String] The ID of the price to create a checkout session for
  # @return [Hash] A hash containing the URL of the checkout session
  def create_checkout_session_for_subscription
    render json: current_user.create_checkout_session_for_subscription(params[:price_id])
  end

  # POST /users/create_customer_portal_session
  #
  # @return [Hash] A hash containing the URL of the customer portal session
  def create_customer_portal_session
    render json: current_user.create_customer_portal_session
  end
end
