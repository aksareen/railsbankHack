from django.conf.urls import url

from . import views
# apis
urlpatterns = [
    url(r'^add_user$', views.add_user, name='add_user'),
    url(r'^handle_transaction', views.handle_transaction, name='handle_transaction'),
    url(r'^credit_account$', views.credit_account, name='credit_account'),
    url(r'^add_new_bank_account', views.add_new_bank_account, name='add_new_bank_account'),
    url(r'^add_bank_account$', views.add_bank_account, name='add_bank_account'),
    url(r'^get_bank_accounts$', views.get_bank_accounts, name='get_bank_accounts'),
    url(r'^get_user_details', views.get_user_details, name='get_user_details'),
    # get total balance from all bank accounts
    url(r'^sign_in$', views.sign_in, name='sign_in'),
    url(r'^csrf_token$', views.get_csrf_token, name='csrf_token'),
]