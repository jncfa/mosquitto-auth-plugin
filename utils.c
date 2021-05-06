/*
 * Function: mosquitto_sub_topic_tokenise
 *
 * Tokenise a topic or subscription string into an array of strings
 * representing the topic hierarchy.
 *
 * For example:
 *
 *    subtopic: "a/deep/topic/hierarchy"
 *
 *    Would result in:
 *
 *       topics[0] = "a"
 *       topics[1] = "deep"
 *       topics[2] = "topic"
 *       topics[3] = "hierarchy"
 *
 *    and:
 *
 *    subtopic: "/a/deep/topic/hierarchy/"
 *
 *    Would result in:
 *
 *       topics[0] = NULL
 *       topics[1] = "a"
 *       topics[2] = "deep"
 *       topics[3] = "topic"
 *       topics[4] = "hierarchy"
 *
 * Parameters:
 *	subtopic - the subscription/topic to tokenise
 *	topics -   a pointer to store the array of strings
 *	count -    an int pointer to store the number of items in the topics array.
 *
 * Returns:
 *	MOSQ_ERR_SUCCESS -        on success
 * 	MOSQ_ERR_NOMEM -          if an out of memory condition occurred.
 * 	MOSQ_ERR_MALFORMED_UTF8 - if the topic is not valid UTF-8
 *
 * Example:
 *
 * > char **topics;
 * > int topic_count;
 * > int i;
 * >
 * > mosquitto_sub_topic_tokenise("$SYS/broker/uptime", &topics, &topic_count);
 * >
 * > for(i=0; i<token_count; i++){
 * >     printf("%d: %s\n", i, topics[i]);
 * > }
 *
 * See Also:
 *	<mosquitto_sub_topic_tokens_free>
 */
#include "utils.h"
#include "mosquitto_broker.h"
/*
 * Search through `in' for tokens %c (clientid) and %u (username); build a
 * new malloc'd string at `res' with those tokens interpolated into it.
 */

void t_expand(const char *clientid, const char *username, const char *in, char **res)
{
	const char *s;
	char *work, *wp;
	int c_specials = 0, u_specials = 0, len;
	const char *ct, *ut;

	ct = (clientid) ? clientid : "";
	ut = (username) ? username : "";

	for (s = in; s && *s; s++)
	{
		if (*s == '%' && (*(s + 1) == 'c'))
			c_specials++;
		if (*s == '%' && (*(s + 1) == 'u'))
			u_specials++;
	}
	len = strlen(in) + 1;
	len += strlen(clientid) * c_specials;
	len += strlen(username) * u_specials;

	if ((work = mosquitto_malloc(len)) == NULL)
	{
		*res = NULL;
		return;
	}
	for (s = in, wp = work; s && *s; s++)
	{
		*wp++ = *s;
		if (*s == '%' && (*(s + 1) == 'c'))
		{
			*--wp = 0;
			strcpy(wp, ct);
			wp += strlen(ct);
			s++;
		}
		if (*s == '%' && (*(s + 1) == 'u'))
		{
			*--wp = 0;
			strcpy(wp, ut);
			wp += strlen(ut);
			s++;
		}
	}
	*wp = 0;

	*res = work;
}