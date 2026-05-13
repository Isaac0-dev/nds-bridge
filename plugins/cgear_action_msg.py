ACTION_MESSAGES = [
    "[TAG:0100:0] is nearby.",
    "[TAG:0100:0] started battling a wild [TAG:0101:1]!",
    "[TAG:0100:0] won the battle with the wild [TAG:0101:1]!",
    "[TAG:0100:0] started battling a special Pokémon!",
    "[TAG:0100:0] won the battle with the special Pokémon!",
    "[TAG:0100:0] started a battle with [TAG:010E:1] [TAG:0100:2]!",
    "[TAG:0100:0] won the battle with [TAG:010E:1] [TAG:0100:2]!",
    "[TAG:0100:0] started a battle with a Gym Leader!",
    "[TAG:0100:0] won the battle with the Gym Leader!",
    "[TAG:0100:0] started a battle with a special Trainer!",
    "[TAG:0100:0] won the battle with a special Trainer!",
    "[TAG:0100:0] started a battle with a special Trainer!",
    "[TAG:0100:0] won the battle with a special Trainer!",
    "[TAG:0100:0] caught a wild [TAG:0101:1]!",
    "[TAG:0100:0] caught a special Pokémon!",
    "[TAG:0100:0]'s [TAG:0102:2]'s level went up!",
    "[TAG:0100:0]'s [TAG:0102:2] evolved into [TAG:0101:1]!",
    "Dummy Message",
    "[TAG:0100:0] found [TAG:0109:1]!",
    "[TAG:0100:0]'s playing time has exceeded [TAG:0202:1] hours!",
    "[TAG:0100:0] completed the Pokédex!",
    "[TAG:0100:0] has been thanked more than [TAG:0202:1] times!",
    "[TAG:0100:0] is in the reception area of the Union Room.",
    "[TAG:0100:0] thanked you!",
    "[TAG:0101:1] is currently being distributed!",
    "The [TAG:0109:1] is currently being distributed!",
    "A Mystery Gift is currently being distributed!",
    "[TAG:0100:0]'s [TAG:0102:2]'s attack was a critical hit!",
    "[TAG:0100:0]'s [TAG:0102:2] took a critical hit!",
    "[TAG:0100:0] escaped from the battle!",
    "[TAG:0100:0]'s [TAG:0102:2] has very low HP!",
    "[TAG:0100:0]'s [TAG:0102:2] has very low PP!",
    "[TAG:0100:0]'s [TAG:0102:2] has fainted!",
    "[TAG:0100:0]'s [TAG:0102:2] has a status condition!",
    "[TAG:0100:0] used [TAG:0109:1]!",
    "[TAG:0100:0] used [TAG:0107:1]!",
    "[TAG:0100:0] received an Egg!",
    "[TAG:0101:1] hatched from [TAG:0100:0]'s Egg!",
    "[TAG:0100:0] is shopping.",
    "[TAG:0100:0] is in a Battle Subway challenge.",
    "[TAG:0100:0] has [TAG:0200:1] straight wins in the Battle Subway!",
    "[TAG:0100:0] won a trophy in the Battle Subway!",
    "[TAG:0100:0] challenged the Battle Institute.",
    "[TAG:0100:0] was certified as [TAG:013D:1] in the Battle Institute!",
    "[TAG:0100:0] got on the Ferris wheel.",
    "[TAG:0100:0] entered the Poké Transfer.",
    "[TAG:0100:0]'s [TAG:0102:2] is currently participating in the Musical contest.",
    "[TAG:0100:0] used the received [TAG:0110:1]!",
    "[TAG:0100:0] said '[TAG:011C:1].'",
    "dummy message",
    "[TAG:0100:0] is shooting [TAG:013F:1] in Pokéstar Studios.",
    "[TAG:0100:0] is watching [TAG:013F:1] in Pokéstar Studios.",
    "[TAG:0100:0] is challenging the [TAG:013B:1].",
    "[TAG:0100:0] won in Round [TAG:0200:2] in the [TAG:013B:1].",
    "[TAG:0100:0] lost in Round [TAG:0200:2] in the [TAG:013B:1].",
    "[TAG:0100:0] won the [TAG:013B:1]!",
    "[TAG:0100:0] is shopping on Join Avenue.",
    "[TAG:0100:0] cleared Area [TAG:0201:2] in [TAG:0105:1]!",
    "[TAG:0100:0] is challenging Area [TAG:0201:2] in [TAG:0105:1].",
]


def message_from_action_id(beacon, action_id):
    msg = ACTION_MESSAGES[action_id + 1]

    player_name = beacon.name

    msg = msg.replace("[TAG:0100:0]", player_name)
    # msg = msg.replace("[TAG:0101:1]", target_name)
    # msg = msg.replace("[TAG:0102:2]", target_name)
    # msg = msg.replace("[TAG:010E:1]", target_name)
    # msg = msg.replace("[TAG:0109:1]", target_name)
    # msg = msg.replace("[TAG:0202:1]", target_name)
    # msg = msg.replace("[TAG:0200:1]", target_name)
    # msg = msg.replace("[TAG:013D:1]", target_name)

    return msg
