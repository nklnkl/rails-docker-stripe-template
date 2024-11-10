class User < ApplicationRecord
  include Devise::JWT::RevocationStrategies::Allowlist

  has_many :allowlisted_jwts, dependent: :destroy

  after_create :create_stripe_customer

  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable, :trackable,
         :jwt_authenticatable, jwt_revocation_strategy: self

  # @param jti [String] The JTI of the JWT to find
  # @return [AllowlistedJwt] The JWT for the user
  def jwt(jti)
    allowlisted_jwts.find_by!(jti: jti)
  end

  # @return [Array<Hash>] An array of hashes containing the JTI, expiration time, and user agent of the user's active JWTs
  def active_jwts
    allowlisted_jwts.where("exp > ?", Time.current).map do |jwt|
      {
        jti: jwt.jti,
        expires_at: jwt.exp,
        user_agent: jwt.aud
      }
    end
  end

  # @param jti [String] The JTI of the JWT to delete
  # @return [void] Deletes the JWT for the user
  def delete_jwt(jti)
    jwt = jwt(jti)
    jwt.destroy
  end

  # @return [void] Deletes all JWTs for the user
  def delete_all_jwts
    allowlisted_jwts.destroy_all
  end

  # @return [Array<Stripe::Subscription>] The user's active subscriptions
  def active_subscriptions
    subscriptions = Stripe::Subscription.list({
      customer: stripe_customer_id,
      status: "all"
    })
    statuses = %w[active trialing]
    subscriptions.data.select { |subscription| statuses.include?(subscription.status) }
  end

  # @return [Boolean] Whether the user has an active subscription
  def has_active_subscription?
    active_subscriptions.any?
  end

  # @param price_id [String] The ID of the price to create a checkout session for
  # @return [Hash] A hash containing the URL of the checkout session
  def create_checkout_session_for_subscription(price_id)
    checkout_session = Stripe::Checkout::Session.create({
      customer: stripe_customer_id,
      success_url: "https://example.com/success",
      cancel_url: "https://example.com/cancel",
      line_items: [{
        price: price_id,
        quantity: 1
      }],
      mode: "subscription"
    })
    { url: checkout_session.url }
  rescue Stripe::StripeError => e
    Rails.logger.error "Failed to create checkout session: #{e.message}"
    raise
  end

  # @return [Hash] A hash containing the URL of the customer portal session
  def create_customer_portal_session
    customer_portal_session = Stripe::BillingPortal::Session.create({
      customer: stripe_customer_id
    })
    { url: customer_portal_session.url }
  end

  private

  # @return [void] Creates a Stripe customer for the user
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
