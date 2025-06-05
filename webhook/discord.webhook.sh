#!/usr/bin/env bash

        ## Get message from argument

        MESSAGE="$@"

        # Functions.

        WEBHOOK() {

                  ## Format to parse to curl
                  MSG_CONTENT=\"$MESSAGE\"

                  ## Discord Webhook
                  URL='https://discord.com/api/webhooks/1367144752021110845/80tw0a2pZaOKtOjqgmcNd_PIrcFimEoABo_lZEv_xi5QoW7tqyaCBE0nB7CEvZxcc21L'

                  ## Sending the message to discord
                  curl -H "Content-Type: application/json" -X POST -d "{\"content\": $MSG_CONTENT}" $URL

        }

        sleep 60

        WEBHOOK

        exit 0
