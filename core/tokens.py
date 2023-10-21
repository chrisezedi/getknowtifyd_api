from django.contrib.auth.tokens import PasswordResetTokenGenerator


class GenerateActivationLink(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
                str(user.is_active) + str(user.pk) + str(timestamp)
        )


token_generator = GenerateActivationLink()
