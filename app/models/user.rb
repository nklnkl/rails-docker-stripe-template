class User < ApplicationRecord
  include Devise::JWT::RevocationStrategies::Allowlist

  has_many :allowlisted_jwts, dependent: :destroy

  after_create :create_stripe_customer

  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable, :trackable,
         :jwt_authenticatable, jwt_revocation_strategy: self

  def jwt(jti)
    allowlisted_jwts.find_by!(jti: jti)
  end

  def active_jwts
    allowlisted_jwts.where("exp > ?", Time.current).map do |jwt|
      {
        jti: jwt.jti,
        expires_at: jwt.exp,
        user_agent: jwt.aud
      }
    end
  end

  def delete_jwt(jti)
    jwt = jwt(jti)
    jwt.destroy
  end

  def delete_all_jwts
    allowlisted_jwts.destroy_all
  end

  private

  def create_stripe_customer
    customer = Stripe::Customer.create(
      email: email,
      metadata: {
        user_id: id
      }
    )
    update(stripe_customer_id: customer.id)
  rescue Stripe::StripeError => e
    Rails.logger.error "Failed to create Stripe customer: #{e.message}"
    raise
  end
end
