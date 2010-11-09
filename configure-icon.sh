#!/bin/bash
echo 'Registering Icons'
echo 'Attention Icon:'
sudo xdg-icon-resource install --theme hicolor --novendor --size 22 eye-version3-attention.xpm inactcli-attention
echo 'Passive Icon:'
sudo xdg-icon-resource install --theme hicolor --novendor --size 22 eye-version3-passive.xpm inactcli-passive
echo 'Active Icon:'
sudo xdg-icon-resource install --theme hicolor --novendor --size 22 eye-version3-active.xpm inactcli-active
