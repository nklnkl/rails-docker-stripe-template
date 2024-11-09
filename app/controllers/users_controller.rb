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
end
